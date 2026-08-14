"""Run every probe against every tier, for real, and report what escaped.

The matrix is the deliverable. Rows are escapes, columns are isolation tiers,
and each cell is what actually happened on this machine, not what a threat
model predicts. The shape people expect is a staircase: more isolation, fewer
escapes. Where the real matrix is NOT a staircase is the finding.
"""

from __future__ import annotations

import socket
import threading

from .probes import HOST_SECRET_MARKER, PROBES
from .runner import Session, TIERS, run_probe


def _loopback_listener():
    """A peer the network probe can reach without a packet leaving the host."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.recv(16)
                conn.sendall(b"pong")
            finally:
                conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, stop, srv


def run_one(probe, tier, sensitive):
    """One cell. Sets up whatever the probe declared it needs, runs, judges."""
    with Session(f"{probe.key}-{tier.key}") as session:
        code, kwargs = probe.build(session, sensitive)
        marker = kwargs.pop("_marker", None)
        needs_fd = kwargs.pop("_needs_fd", False)
        needs_listener = kwargs.pop("_needs_listener", False)

        fd = None
        port = stop = srv = None
        try:
            if needs_fd:
                # Opened in the PARENT before the child forks, so the child
                # inherits it unless the tier sets close_fds. That inheritance
                # is the leak.
                fd = _open_leaked_fd(sensitive)
                code = code.replace("__FD__", str(fd))
            if needs_listener:
                port, stop, srv = _loopback_listener()
                code = code.replace("__PORT__", str(port))

            result = run_probe(code, tier, session.path, **kwargs)

            if marker is not None:
                escaped, detail = probe.judge(result, marker)
            else:
                escaped, detail = probe.judge(result)
            return {"escaped": escaped, "detail": detail,
                    "timed_out": result.timed_out}
        finally:
            if fd is not None:
                import os
                try:
                    os.close(fd)
                except OSError:
                    pass
            if stop is not None:
                stop.set()
                srv.close()


def _open_leaked_fd(sensitive):
    import os
    # PEP 446: Python marks every fd it creates non-inheritable, so an fd is
    # only "leaked" if something made it inheritable, which is exactly what a
    # careless tool does when it passes handles to a child, or what any
    # non-Python parent does by default. set_inheritable models that leak; the
    # close_fds tier is then the thing that closes it anyway.
    fd = os.open(str(sensitive), os.O_RDONLY)
    os.set_inheritable(fd, True)
    return fd


def build(root):
    """Run the full matrix. `root` is a writable dir for the host secret."""
    sensitive = root / "host_secret.txt"
    sensitive.write_text(HOST_SECRET_MARKER + "\n")
    try:
        cells = {}
        for probe in PROBES:
            cells[probe.key] = {}
            for tier in TIERS:
                cells[probe.key][tier.key] = run_one(probe, tier, sensitive)
        return cells
    finally:
        sensitive.unlink(missing_ok=True)


def format_matrix(cells) -> str:
    from .probes import PROBES as P
    from .runner import TIERS as T
    lines = []
    head = f"  {'escape':<22} " + " ".join(f"{t.key:>11}" for t in T)
    lines.append(head)
    lines.append("  " + "-" * (len(head) - 2))
    for probe in P:
        row = f"  {probe.key:<22} "
        row += " ".join(
            f"{'ESCAPED' if cells[probe.key][t.key]['escaped'] else '  --   ':>11}"
            for t in T)
        lines.append(row)
    return "\n".join(lines)
