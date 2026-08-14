"""What must hold before the matrix is a finding rather than an accident.

Two kinds of test live here. The first kind is about HOST SAFETY: this
repository executes real escapes, so the harness must be provably unable to
harm the machine it runs on, and that is not a comment, it is assertions. The
second kind is about the MATRIX being a measurement: the naked tier must
actually escape, isolation must be monotone, and each staircase close must be
caused by the flag it is attributed to rather than by an accident of the host.

Why portability is asserted separately from monotonicity. A close at the
resource tier can be produced by the HOST rather than by the sandbox:
RLIMIT_NPROC is a per-UID system-wide limit, so on an account already running
more processes than the cap it denies every fork and two escapes stop looking
like isolation working. That result flips on a quieter machine.
Test_isolation_is_monotone cannot see the difference. The portability test
can, because it asserts the close survives a change in ambient process count.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from sandbox import runner
from sandbox.matrix import build, run_one
from sandbox.probes import HOST_SECRET_MARKER, PROBES
from sandbox.runner import TIERS, Session, run_probe

BY_PROBE = {p.key: p for p in PROBES}
BY_TIER = {t.key: t for t in TIERS}


@pytest.fixture(scope="module")
def matrix():
    root = Path(tempfile.mkdtemp(prefix="test-agb-"))
    return build(root)


# ------------------------------------------------------------- host safety

def test_the_cpu_limit_is_meant_to_bite_before_the_harness_gives_up():
    """The tiers' own limit must be tighter than the harness's backstop.

    A spinner at a resource tier can be ended two ways: RLIMIT_CPU, which is
    the SANDBOX stopping it, or the wall clock, which is the HARNESS giving up.
    The first is the thing being measured and the second is a safety net, so
    the constants have to keep them in that order. Raising cpu_seconds above
    WALL_CLOCK_S would leave the harness as the only thing stopping a spin,
    and every tier would look equally good at it.
    """
    for tier in TIERS:
        if tier.cpu_seconds:
            assert tier.cpu_seconds < runner.WALL_CLOCK_S, (
                f"{tier.key} would outlive the harness's own timeout")


def test_a_spinner_hits_the_wall_clock_where_nothing_can_preempt_it():
    """The wall clock itself, measured where it is the ONLY thing that can fire.

    t2_env applies no rlimits, so a spin loop there can only be ended by
    run_probe's own timeout. Asserting timed_out at a RESOURCE tier instead
    would be asserting the outcome of a race: see the test below.
    """
    with Session("spin") as s:
        start = time.time()
        result = run_probe("while True: pass", BY_TIER["t2_env"], s.path)
        elapsed = time.time() - start
    assert result.timed_out
    assert elapsed < runner.WALL_CLOCK_S + 3, "cleanup did not return promptly"


def test_a_spinner_is_dead_and_prompt_at_the_full_tier_however_it_died():
    """A spinning child must be dead when run_probe returns. The whole harness
    rests on this: an escape that hangs cannot be allowed to hang the host.

    Which mechanism kills it is a race, and this test deliberately does not
    pick one. RLIMIT_CPU is 4 seconds of CPU and the wall clock is 5 seconds of
    real time, so on an idle machine the CPU limit wins (SIGKILL, negative
    returncode) and on a loaded one the spinner takes more than 5 seconds of
    real time to burn 4 seconds of CPU and the wall clock wins instead.
    Asserting `result.timed_out` therefore passes or fails on how busy the
    machine is: an idle runner returns returncode -9 with timed_out False.

    The property host safety actually needs is the conjunction below: the child
    did not exit on its own, and run_probe came back promptly. Both hold on
    either branch of the race, so they are what gets asserted.
    """
    with Session("spin") as s:
        start = time.time()
        result = run_probe("while True: pass", BY_TIER["t4_full"], s.path)
        elapsed = time.time() - start
    killed = result.timed_out or (result.returncode is not None
                                  and result.returncode < 0)
    assert killed, f"a spinner ended on its own terms: {result}"
    assert elapsed < runner.WALL_CLOCK_S + 3, "cleanup did not return promptly"


def test_the_only_detaching_probe_self_terminates():
    """proc_grandchild survives killpg by design, setsid defeats it, so
    host safety depends on it exiting ON ITS OWN. If that probe were ever
    edited to sleep longer than a breath, the harness could leave a process
    behind. This pins the self-limit."""
    src = BY_PROBE["proc_grandchild"].build.__code__
    # The grandchild's sleep is a literal in the probe source; assert it is
    # short. Reading the source rather than the behavior so the bound is
    # checked even on a run where the grandchild happens to be reaped.
    import inspect

    from sandbox import probes
    body = inspect.getsource(probes._surviving_grandchild)
    assert "time.sleep(1.5)" in body, (
        "the detaching probe's self-limit changed; re-verify host safety")


def test_rlimits_are_applied_in_the_limited_tiers():
    """RLIMIT_AS and RLIMIT_FSIZE must actually reach the child, or the
    resource tier is decoration and a runaway probe could touch the host."""
    with Session("lim") as s:
        result = run_probe(
            "import resource\n"
            "a = resource.getrlimit(resource.RLIMIT_AS)[0]\n"
            "f = resource.getrlimit(resource.RLIMIT_FSIZE)[0]\n"
            "print(a, f)",
            BY_TIER["t3_rlimits"], s.path)
    assert result.returncode == 0
    a_lim, f_lim = (int(x) for x in result.stdout.split())
    assert a_lim == runner.ADDRESS_SPACE_BYTES
    assert f_lim == runner.MAX_FILE_BYTES


def test_nproc_is_not_used_as_a_control():
    """Pins a defect and its finding. RLIMIT_NPROC is per-UID system-wide, so
    setting it stops escapes by an accident of the host's process count. It was
    removed, and it must stay removed: a child in the limited tier must see the
    INHERITED nproc limit, not one this harness imposed."""
    inherited = resource.getrlimit(resource.RLIMIT_NPROC)
    with Session("np") as s:
        result = run_probe(
            "import resource\n"
            "print(resource.getrlimit(resource.RLIMIT_NPROC)[0])",
            BY_TIER["t4_full"], s.path)
    assert int(result.stdout.strip()) == inherited[0], (
        "the harness is setting RLIMIT_NPROC again; it is a per-UID limit and "
        "not a per-sandbox control")


def test_host_health_check_reads_real_memory():
    ok, msg = runner.host_is_healthy()
    assert isinstance(ok, bool) and "MB" in msg


# ------------------------------------------------------------- the matrix

def test_the_naked_tier_escapes_everything_it_can():
    """t0 is the baseline. Every probe that is escapable at all must escape
    with no isolation, or the probe is not testing what it claims. The two
    exceptions are named: env-scrub cannot matter at t0 (nothing is scrubbed,
    so it DOES escape), and the /proc probe is blocked by the kernel at every
    tier including this one."""
    root = Path(tempfile.mkdtemp(prefix="naked-"))
    cells = build(root)
    for probe in PROBES:
        escaped = cells[probe.key]["t0_naked"]["escaped"]
        if probe.key == "secret_proc_environ":
            assert not escaped        # kernel, not sandbox
        else:
            assert escaped, f"{probe.key} did not escape the naked tier"


def test_isolation_is_monotone(matrix):
    """THE STRUCTURAL INVARIANT. Adding isolation can only remove escapes, never
    add them. Once a probe is stopped at some tier, it must stay stopped at
    every stronger tier. A violation means the tiers are not nested or a probe
    is flaky, and either way the matrix is not a measurement."""
    order = [t.key for t in TIERS]
    for probe in PROBES:
        stopped_at = None
        for tier_key in order:
            escaped = matrix[probe.key][tier_key]["escaped"]
            if not escaped and stopped_at is None:
                stopped_at = tier_key
            if stopped_at is not None:
                assert not escaped, (
                    f"{probe.key} escaped {tier_key} after being stopped at "
                    f"{stopped_at}: isolation is not monotone")


def test_the_flat_escapes_are_flat(matrix):
    """The finding, asserted. Filesystem reach and network egress are unchanged
    from the naked tier to the maximal compute tier, because compute isolation
    is not capability isolation. If a tier ever stops one of these, it acquired
    a capability control and the README's central claim needs revisiting."""
    for key in ("fs_absolute_read", "fs_traversal", "net_loopback",
                "proc_grandchild"):
        for tier in TIERS:
            assert matrix[key][tier.key]["escaped"], (
                f"{key} was stopped at {tier.key}; a capability control "
                f"appeared and the finding has changed")


def test_each_compute_close_happens_at_the_expected_flag(matrix):
    """The staircase, asserted per probe. Each of these escapes is closed by
    exactly one flag and must be open the tier before it and closed the tier
    after. Otherwise it is being closed by something other than the control
    it is attributed to."""
    # (probe, last tier that escapes, first tier that stops it)
    for key, last_open, first_closed in (
            ("secret_env", "t1_cwd", "t2_env"),
            ("res_oversized_write", "t2_env", "t3_rlimits"),
            ("fd_leak", "t3_rlimits", "t4_full")):
        assert matrix[key][last_open]["escaped"], (
            f"{key} should still escape at {last_open}")
        assert not matrix[key][first_closed]["escaped"], (
            f"{key} should be closed at {first_closed}")


def test_the_kernel_block_is_labelled_not_silent(matrix):
    """secret_proc_environ is stopped everywhere by the host kernel, not by any
    tier. That is a different fact from 'the sandbox stopped it', and the cell
    must SAY which, or the matrix credits the sandbox with the kernel's work."""
    for tier in TIERS:
        cell = matrix["secret_proc_environ"][tier.key]
        assert not cell["escaped"]
        assert "kernel" in cell["detail"], (
            "the /proc block is reported without naming the kernel, so it "
            "reads as a sandbox win")


def test_a_resource_close_is_portable():
    """Directly guards the NPROC defect. The resource close must survive a
    change in the host's ambient process count. RLIMIT_FSIZE is per-process and
    passes this; RLIMIT_NPROC did not, so it is gone. Runs the probe twice and
    requires the same verdict."""
    root = Path(tempfile.mkdtemp(prefix="port-"))
    sensitive = root / "s.txt"
    sensitive.write_text(HOST_SECRET_MARKER)
    probe = BY_PROBE["res_oversized_write"]
    first = run_one(probe, BY_TIER["t3_rlimits"], sensitive)
    # Spawn transient processes to move the ambient count, then re-measure.
    kids = [subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"])
            for _ in range(8)]
    try:
        second = run_one(probe, BY_TIER["t3_rlimits"], sensitive)
    finally:
        for k in kids:
            k.wait()
    assert first["escaped"] == second["escaped"] is False


def test_the_matrix_is_reproducible():
    """Two builds must agree on every cell. A cell that flickers is not a
    measurement, and every table in the README is one build."""
    a = build(Path(tempfile.mkdtemp(prefix="r1-")))
    b = build(Path(tempfile.mkdtemp(prefix="r2-")))
    for probe in PROBES:
        for tier in TIERS:
            assert (a[probe.key][tier.key]["escaped"]
                    == b[probe.key][tier.key]["escaped"]), (
                f"{probe.key}/{tier.key} was not reproducible")


def test_no_probe_leaves_a_session_directory_behind():
    """Cleanup runs even when a probe escapes. A harness that measures
    filesystem escapes must not itself litter the filesystem."""
    before = set(Path(tempfile.gettempdir()).glob("sbx-*"))
    with Session("cleanup") as s:
        run_probe("print('x')", BY_TIER["t0_naked"], s.path)
        path = s.path
        assert path.exists()
    assert not path.exists()
    after = set(Path(tempfile.gettempdir()).glob("sbx-*"))
    assert after <= before
