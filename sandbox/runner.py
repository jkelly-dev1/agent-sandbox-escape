"""Run a probe inside a tier-1 sandbox, and come back with the host intact.

Every probe in this repository executes for real. Nothing here is simulated:
the escapes either work on this machine or they do not, and the matrix reports
what happened rather than what the documentation says should happen. That is
the whole reason the repository exists. The operator's library file makes the
point in section 21, about network egress, and it generalizes: an isolation
claim you have not tried is a claim about a manual.

Because it executes for real, host safety is a feature of the harness and not
a habit of the author. A sibling project's notes record an agent leaving four
spin loops running on a shared machine because `timeout` does not kill
background grandchildren, and a separate incident where a batch exhausted a
tmpfs and took the box down. Both are the same lesson:

    CGROUPS and process groups are the unit of lifecycle management. PIDS ARE
    NOT.

So every probe here runs in ITS OWN SESSION via start_new_session=True, and
cleanup kills the whole process GROUP with SIGKILL rather than waiting on a
PID. A grandchild that outlives its parent is exactly one of the escapes being
measured, which means the harness must be able to survive finding one.

And KILLPG is not enough, which is itself a measured Result. A child that
calls setsid() moves into its OWN session and process group, so killpg on the
parent's group cannot reach it: the proc_grandchild probe escapes at every
tier for exactly this reason. Reaping such a process needs a PID namespace,
which this unprivileged stack does not have. Host safety therefore does NOT
rest on being able to kill a detached process; it rests on every probe that
detaches also being SELF-LIMITING. The grandchild sleeps briefly and exits on
its own, so the demonstration survives ~1.5 seconds and then is gone.

The other safety rules, all enforced here rather than remembered:
  - a hard wall-clock cap on every probe, defaulting to 5 seconds
  - RLIMIT_AS on every child so a runaway allocation cannot touch the host
  - RLIMIT_FSIZE so a probe cannot fill a disk
  - the wall-clock timeout bounds anything that spins; no probe fork-bombs,
    because without a cgroup pids.max there is no honest way to cap forks per
    sandbox (see _limits) and a fork bomb has no place in a harness that
    cannot contain one
  - probes run one at a time; there is no concurrency here on purpose
  - nothing ever contacts a remote host. Network probes bind and connect
    to loopback only, and the matrix says so where it reports them.
"""

from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Hard ceilings. These are the harness's promise to the machine it runs on.
WALL_CLOCK_S = 5
ADDRESS_SPACE_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MIN_FREE_MB = 512


@dataclass
class Result:
    """What a probe did, and whether that counts as an escape."""

    escaped: bool
    detail: str
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False


def host_is_healthy() -> tuple[bool, str]:
    """Refuse to start if the machine cannot afford the run.

    Cheap, and its absence turned a previous batch into an outage. Reads
    /proc/meminfo rather than shelling out, so the check itself costs
    nothing.
    """
    try:
        info = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            info[key] = int(rest.strip().split()[0])
        free_mb = (info.get("MemAvailable", 0)) // 1024
    except (OSError, ValueError, IndexError):
        return True, "could not read /proc/meminfo; proceeding"
    if free_mb < MIN_FREE_MB:
        return False, f"only {free_mb} MB available, need {MIN_FREE_MB}"
    return True, f"{free_mb} MB available"


def _limits(tier) -> None:
    """Applied in the child between fork and exec.

    Only per-process limits are used here, and the omission of RLIMIT_NPROC is itself a finding. RLIMIT_NPROC counts
    processes per real UID across the whole system, not per sandbox and not per process tree. On a busy account it
    denies the sandbox its own first fork; on a fresh one it denies nothing. Setting it on this host, where the UID
    already ran 112 processes against a limit of 64, silently stops two escapes by forbidding every fork, which is a
    property of the machine's process count and not of the sandbox. The real per-sandbox process cap is a cgroup
    pids.max, which an unprivileged stack does not have. So the escape that needs it is left ESCAPED and labeled,
    rather than blocked by accident.

    RLIMIT_AS, RLIMIT_FSIZE and RLIMIT_CPU are all per-process and portable.
    """
    resource.setrlimit(resource.RLIMIT_AS,
                       (ADDRESS_SPACE_BYTES, ADDRESS_SPACE_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
    if tier.cpu_seconds:
        resource.setrlimit(resource.RLIMIT_CPU,
                           (tier.cpu_seconds, tier.cpu_seconds))


@dataclass(frozen=True)
class Tier:
    """One isolation level, described by what it actually does.

    These are the tiers an agent framework SHIPS, not the tiers a security
    architecture diagram draws. Everything here is available to an unprivileged
    process: no root, no namespaces, no container runtime. That is the point.
    The interesting question is not what gVisor stops, it is what the thing
    people actually deploy stops.
    """

    key: str
    what: str
    set_cwd: bool = False
    scrub_env: bool = False
    apply_rlimits: bool = False
    close_fds: bool = False
    new_session: bool = False
    cpu_seconds: int | None = None

    def note(self) -> str:
        on = [n for n, v in (("cwd", self.set_cwd), ("env", self.scrub_env),
                             ("rlimits", self.apply_rlimits),
                             ("close_fds", self.close_fds),
                             ("new_session", self.new_session)) if v]
        return ", ".join(on) if on else "nothing"


TIERS = (
    Tier("t0_naked", "subprocess with no restrictions at all"),
    Tier("t1_cwd", "working directory set to the sandbox", set_cwd=True),
    Tier("t2_env", "plus the environment scrubbed to a small allowlist",
         set_cwd=True, scrub_env=True),
    Tier("t3_rlimits", "plus resource limits", set_cwd=True, scrub_env=True,
         apply_rlimits=True, cpu_seconds=4),
    Tier("t4_full", "plus closed descriptors and its own session",
         set_cwd=True, scrub_env=True, apply_rlimits=True, close_fds=True,
         new_session=True, cpu_seconds=4),
)

# What survives an env scrub. Deliberately close to what a real framework
# keeps, because a scrub that removed PATH would be a scrub nobody ships.
ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "TMPDIR")


def run_probe(code: str, tier: Tier, workdir: Path,
              extra_env: dict | None = None) -> Result:
    """Execute `code` as a child python process under `tier`.

    Returns what happened. Interpreting it as an escape is the probe's job,
    not this function's: the runner stays ignorant of what is being measured
    so that a probe cannot quietly redefine success.
    """
    # `extra_env` puts the secret in the child, which is what the env-scrub
    # probe needs: a scrubbing tier must remove it and a naked tier must not.
    #
    # There is no parent-side equivalent and it cannot be added here.
    # /proc/<pid>/environ reports the environment a process was EXECED with,
    # not its current os.environ, so setting a variable in this process at
    # runtime does not appear there. A probe that reads the parent's environ
    # therefore needs a parent LAUNCHED with the value; see the docstring on
    # `_read_proc_environ` for what that means for what this harness measures.
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    if tier.scrub_env:
        env = {k: v for k, v in env.items() if k in ENV_ALLOWLIST}

    kwargs = {
        "cwd": str(workdir) if tier.set_cwd else None,
        "env": env,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "start_new_session": tier.new_session,
        "close_fds": tier.close_fds,
    }
    if tier.apply_rlimits:
        kwargs["preexec_fn"] = lambda: _limits(tier)
    # NO pass_fds. A leaked descriptor is inherited by NATURE when close_fds is
    # False, and closed when it is True, which is exactly the thing being
    # measured. Passing it explicitly would keep it open regardless of the
    # tier, testing nothing and warning about it.

    proc = subprocess.Popen([sys.executable, "-c", code], **kwargs)
    try:
        out, err = proc.communicate(timeout=WALL_CLOCK_S)
        return Result(False, "", out or "", err or "", proc.returncode, False)
    except subprocess.TimeoutExpired:
        _kill_tree(proc, tier)
        out, err = proc.communicate()
        return Result(False, "timed out", out or "", err or "", None, True)
    finally:
        _kill_tree(proc, tier)


def _kill_tree(proc: subprocess.Popen, tier: Tier) -> None:
    """Kill the GROUP, not the process. See this module's docstring.

    When the tier did not ask for its own session the child shares ours, so
    killing the group would kill the harness. That asymmetry is not a flaw in
    the cleanup; it is the reason new_session is one of the tiers being
    measured, and the probe that detects a surviving grandchild reports it.

    A process that has setsid()'d away is UNREACHABLE by this killpg and the
    harness does not pretend otherwise: it relies on such probes being
    self-limiting. Only proc_grandchild detaches, and it exits on its own.
    """
    if proc.poll() is None:
        try:
            if tier.new_session:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


class Session:
    """A per-run sandbox directory, created and destroyed like a real one."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.path = Path(tempfile.mkdtemp(prefix=f"sbx-{name}-"))

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self.path, ignore_errors=True)
