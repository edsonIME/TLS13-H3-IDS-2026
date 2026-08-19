#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runlib.py — shared helpers for the LAB AUTOMATION layer (capture / orchestration /
monitoring) [audit v20.26].

These orchestration scripts (preflight, capture_run, process_pcap, service_monitor,
clock_evidence, finalize_run, orchestrate_run, orchestrate_campaign) are the missing
"outer shell" around the already-tested analytical pipeline: they capture the PCAP,
run Zeek, drive the existing tools (benign_traffic / run_attacks / label_flows /
correlate_ground_truth / merge_and_split / validate_dataset / evaluate_realism) and
seal each run with hashes — they do NOT re-implement any analytics.

DESIGN NOTES
- Everything an orchestration step does goes through a `Runner`, so the SAME step code
  runs `local` (subprocess on this host) or over `ssh` to another notebook (NB1..NB4).
  This keeps the state machine testable with a fake/local runner and dependency-free
  (we shell out to the system `ssh`, no paramiko).
- Every artifact is JSON (or CSV) and every produced file is SHA-256'd, so a run can be
  sealed and later re-verified — the provenance discipline the analytical layer already
  uses [audit 6].
- Nothing here needs root or the physical lab to be IMPORTED or unit-tested; the parts
  that DO need the lab (tcpdump, zeek, chronyc, the victims) are isolated behind small
  functions and a `--dry-run`/injectable-runner seam.
"""

import datetime
import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
import time

TOOL_VERSION = "lab_orchestration/v22"    # automation-layer banner. v22 = judge the plan by the KNOWN plan,
                                          # not the report's own flags: the finalizer DERIVES the critical
                                          # steps (start_capture/attacks/process_pcap/label_flows) and requires
                                          # each to have run and PASSED regardless of the report's `required`
                                          # field, rejects non-object step entries, and confronts the report's
                                          # tool_version with the current banner; benign sessions must be
                                          # SEQUENTIAL (non-overlapping) so millisecond-shifted near-clones are
                                          # rejected [audit v20.47]


# --------------------------------------------------------------------------- time / io

def utc_now_iso():
    """Timezone-aware UTC timestamp, e.g. '2026-07-20T12:00:00.000000+00:00'."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_file(path):
    """Streaming SHA-256 of a file (chunked, so a multi-GB PCAP never loads into RAM)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data):
    """SHA-256 of a bytes/str payload (str is UTF-8 encoded)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def write_json(path, obj):
    """Write `obj` as pretty, strict JSON (no NaN/Inf) and return its SHA-256. The write is
    ATOMIC (temp + os.replace) so a killed process never leaves a half-written artifact."""
    payload = json.dumps(obj, indent=2, sort_keys=True, allow_nan=False)
    tmp = path + ".tmp"
    # ensure the target directory exists (a reboot wipes /tmp staging dirs;
    # callers shouldn't have to pre-create it) [robustness fix]
    _d = os.path.dirname(path)
    if _d:
        os.makedirs(_d, exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(payload)
    os.replace(tmp, path)
    return sha256_bytes(payload)


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def ensure_run_dir(base, run_id, overwrite=False):
    """Create (or reuse) the directory for run <run_id> under `base`. A run directory is a
    WORM-ish boundary: creating one that already exists ABORTS unless --overwrite, so a
    second capture can never silently clobber a previous run's evidence [audit 5/11]."""
    d = os.path.join(base, "run{}".format(run_id))
    if os.path.isdir(d) and os.listdir(d) and not overwrite:
        raise FileExistsError(
            "run directory {} already exists and is non-empty; pass --overwrite to replace "
            "it (a run is never silently clobbered)".format(d))
    os.makedirs(d, exist_ok=True)
    return d


# --------------------------------------------------------------------------- subprocess

class CmdResult(object):
    """The outcome of one command: return code, captured stdout/stderr, wall time, argv."""

    def __init__(self, argv, returncode, stdout, stderr, seconds, timed_out=False):
        self.argv = argv
        self.returncode = returncode
        self.stdout = stdout or ""
        self.stderr = stderr or ""
        self.seconds = seconds
        self.timed_out = timed_out

    @property
    def ok(self):
        return self.returncode == 0 and not self.timed_out

    def as_dict(self):
        return {"argv": self.argv, "returncode": self.returncode, "seconds": round(self.seconds, 3),
                "timed_out": self.timed_out, "stdout_tail": self.stdout[-2000:],
                "stderr_tail": self.stderr[-2000:]}


def run_cmd(argv, timeout=None, cwd=None, env=None):
    """Run `argv` (a list), capturing output with a hard timeout. On timeout the whole process
    GROUP is killed (start_new_session) so a hung child never wedges the orchestrator — the same
    discipline the test runner uses. Returns a CmdResult (never raises for a non-zero rc)."""
    import time
    t0 = time.time()
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=cwd, env=env, text=True, encoding="utf-8",
                                 errors="replace", start_new_session=True)
    except (OSError, ValueError) as exc:
        return CmdResult(argv, 127, "", "could not start {}: {}".format(argv, exc), time.time() - t0)
    try:
        out, err = proc.communicate(timeout=timeout)
        return CmdResult(argv, proc.returncode, out, err, time.time() - t0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, err = proc.communicate()
        return CmdResult(argv, -9, out, err, time.time() - t0, timed_out=True)


def which(binary):
    """Absolute path of `binary` on PATH, or None (used by preflight to check tool presence)."""
    import shutil
    return shutil.which(binary)


def tool_version(binary, version_arg="--version"):
    """Best-effort '<binary> --version' first line, or None if the tool is absent/errors."""
    if which(binary) is None:
        return None
    r = run_cmd([binary, version_arg], timeout=10)
    text = (r.stdout or r.stderr).strip().splitlines()
    return text[0] if text else None


# --------------------------------------------------------------------------- runners

class BgJob(object):
    """A handle to a BACKGROUND job started on a host — capture/monitor/benign run CONCURRENTLY while
    attacks run in the foreground, so the PCAP actually contains the attacks [audit v20.27 §2/§6]."""

    def __init__(self, runner, pid, popen=None, target=None, log_path=None, name=""):
        self.runner, self.pid, self.popen = runner, pid, popen
        self.target, self.log_path, self.name = target, log_path, name


class Runner(object):
    """Executes a command on some HOST. Subclasses differ only in HOW they reach the host, so an
    orchestration step is written once and runs locally in tests and over ssh in the lab. Beyond `run`
    (foreground), a Runner can START/WAIT/STOP background jobs and FETCH/PUSH files [audit v20.27]."""

    name = "runner"

    def run(self, argv, timeout=None):                     # pragma: no cover - interface
        raise NotImplementedError

    def start_background(self, argv, log_path=None, name=""):   # pragma: no cover - interface
        raise NotImplementedError

    def wait_background(self, job, timeout=None):          # pragma: no cover - interface
        raise NotImplementedError

    def stop_background(self, job, grace=3.0):             # pragma: no cover - interface
        raise NotImplementedError

    def fetch(self, remote_path, local_path):             # pragma: no cover - interface
        raise NotImplementedError

    def push(self, local_path, remote_path):              # pragma: no cover - interface
        raise NotImplementedError

    def mkdir(self, path):                                # pragma: no cover - interface
        """Create `path` (and parents) ON THIS runner's host — a remote staging dir must exist before a
        background job redirects its log into it [audit v20.28 §6]."""
        raise NotImplementedError

    def exists(self, path):                               # pragma: no cover - interface
        """True if `path` exists on this runner's host (used by readiness probes) [audit v20.28 §5]."""
        raise NotImplementedError

    def file_size(self, path):                            # pragma: no cover - interface
        """Size of `path` on this host, or -1 if absent (readiness: is the PCAP GROWING?)."""
        raise NotImplementedError


class LocalRunner(Runner):
    """Runs on THIS machine (used for the sensor's own steps and for all tests)."""

    name = "local"

    def run(self, argv, timeout=None):
        return run_cmd(list(argv), timeout=timeout)

    def start_background(self, argv, log_path=None, name=""):
        log = open(log_path, "w") if log_path else subprocess.DEVNULL
        p = subprocess.Popen(list(argv), stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        return BgJob(self, p.pid, popen=p, log_path=log_path, name=name)

    def wait_background(self, job, timeout=None):
        try:
            return job.popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None                                    # still running

    def stop_background(self, job, grace=3.0):
        p = job.popen
        if p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGINT)   # let the child (tcpdump) flush + write stats
            except (ProcessLookupError, PermissionError):
                pass
            try:
                p.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        return p.poll()

    def fetch(self, remote_path, local_path):              # "remote" == this machine
        import shutil
        shutil.copy(remote_path, local_path)
        return True

    def push(self, local_path, remote_path):
        import shutil
        shutil.copy(local_path, remote_path)
        return True

    def mkdir(self, path):
        os.makedirs(path, exist_ok=True)
        return True

    def exists(self, path):
        return os.path.exists(path)

    def file_size(self, path):
        return os.path.getsize(path) if os.path.exists(path) else -1


class SSHRunner(Runner):
    """Runs on a REMOTE notebook over the system `ssh` (dependency-free). BatchMode=yes so a missing
    key fails fast instead of prompting; the caller supplies `user@host` and an optional key/port.
    NOTE: key-based auth must be set up out of band — this layer never handles passwords."""

    def __init__(self, target, key=None, port=None, extra_opts=None):
        self.target = target
        self.name = "ssh:" + target
        self._key, self._port, self._extra = key, port, list(extra_opts or [])
        self._base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        if key:
            self._base += ["-i", key]
        if port:
            self._base += ["-p", str(port)]
        if extra_opts:
            self._base += list(extra_opts)

    def _scp_base(self):
        """scp shares ssh's opts but spells the port -P (capital) — build a matching base."""
        base = ["scp", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        if self._key:
            base += ["-i", self._key]
        if self._port:
            base += ["-P", str(self._port)]
        return base + self._extra

    def run(self, argv, timeout=None):
        remote = argv if isinstance(argv, str) else " ".join(shlex.quote(a) for a in argv)
        return run_cmd(self._base + [self.target, remote], timeout=timeout)

    def start_background(self, argv, log_path=None, name=""):
        """Start a detached remote job (nohup ... &) and capture its PID via `echo $!`. The remote
        log defaults to a per-run tmp file so stop/wait can act on the PID."""
        remote = argv if isinstance(argv, str) else " ".join(shlex.quote(a) for a in argv)
        log = log_path or "/tmp/labbg_{}.log".format(int(time.time()))
        launch = "nohup {} > {} 2>&1 & echo $!".format(remote, shlex.quote(log))
        r = self.run(launch, timeout=30)
        pid = None
        if r.ok:
            tail = (r.stdout or "").strip().splitlines()
            pid = tail[-1].strip() if tail else None
        return BgJob(self, pid, target=self.target, log_path=log, name=name)

    def wait_background(self, job, timeout=None):
        """Poll `kill -0 <pid>` until the remote process is gone (rc!=0). Returns 0 when finished,
        None on timeout — mirrors LocalRunner's contract."""
        end = time.time() + (timeout if timeout is not None else 0)
        while True:
            chk = self.run("kill -0 {} 2>/dev/null && echo UP || echo GONE".format(job.pid), timeout=15)
            if "GONE" in (chk.stdout or ""):
                return 0
            if timeout is not None and time.time() >= end:
                return None
            time.sleep(1)

    def stop_background(self, job, grace=3.0):
        """SIGINT the remote PID (so tcpdump flushes), wait `grace`, then SIGKILL as a backstop."""
        self.run("kill -INT {} 2>/dev/null || true".format(job.pid), timeout=15)
        time.sleep(grace)
        self.run("kill -KILL {} 2>/dev/null || true".format(job.pid), timeout=15)
        return 0

    def fetch(self, remote_path, local_path):
        """Copy a file FROM the remote notebook to this host (scp). Used to pull NB3's ground-truth
        annotations onto NB4 so labeling sees them [audit v20.27 §6]."""
        r = run_cmd(self._scp_base() + ["{}:{}".format(self.target, remote_path), local_path], timeout=300)
        return r.ok

    def push(self, local_path, remote_path):
        """Copy a file FROM this host TO the remote notebook (scp)."""
        r = run_cmd(self._scp_base() + [local_path, "{}:{}".format(self.target, remote_path)], timeout=300)
        return r.ok

    def mkdir(self, path):
        return self.run("mkdir -p {}".format(shlex.quote(path)), timeout=30).ok

    def exists(self, path):
        r = self.run("test -e {} && echo YES || echo NO".format(shlex.quote(path)), timeout=30)
        return "YES" in (r.stdout or "")

    def file_size(self, path):
        r = self.run("stat -c %s {} 2>/dev/null || echo -1".format(shlex.quote(path)), timeout=30)
        tail = (r.stdout or "").strip().splitlines()
        try:
            return int(tail[-1]) if tail else -1
        except ValueError:
            return -1


class WindowsRunner(Runner):
    """Runs on a REMOTE **Windows** notebook over OpenSSH, but with WINDOWS-native commands so NB2 keeps
    its native browser/TLS stack — real Windows JA3/JA3S fingerprints — instead of Linux/WSL ones
    [audit v20.28 §7]. Everything is dispatched through `powershell`; background jobs use
    `Start-Process -PassThru` (a real PID), stop uses `Stop-Process`, and files move with the Windows
    OpenSSH `scp`. Paths are Windows paths (C:\\...). The command BUILDERS are pure so they can be
    unit-tested without a Windows host (which this Linux sandbox cannot provide)."""

    def __init__(self, target, key=None, port=None, extra_opts=None, python="python"):
        self.target = target
        self.name = "win:" + target
        self._key, self._port, self._extra = key, port, list(extra_opts or [])
        self._python = python                              # Windows ships `python`, not `python3`
        self._base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        if key:
            self._base += ["-i", key]
        if port:
            self._base += ["-p", str(port)]
        if extra_opts:
            self._base += list(extra_opts)

    # ---- pure builders (unit-tested) ----
    def _win_cmdline(self, argv):
        """Turn an argv list into a Windows command line, mapping the pipeline's `python3` to the
        Windows `python`. Args are double-quoted (cmd/PowerShell convention)."""
        if isinstance(argv, str):
            return argv
        parts = []
        for i, a in enumerate(argv):
            a = self._python if (i == 0 and a in ("python3", "python")) else str(a)
            parts.append('"{}"'.format(a) if (" " in a or a == "") else a)
        return " ".join(parts)

    def _pwsh(self, inner):
        """Wrap a PowerShell snippet for remote ssh execution via -EncodedCommand.

        The snippet uses SINGLE-quoted PowerShell strings (Start-Process -ArgumentList '...'); routing
        those through -Command "..." forces backslash-escaping that PowerShell does not honour, so the
        args arrived corrupted (literal \' in -FilePath) and the process never launched. -EncodedCommand
        takes base64(UTF-16LE) and needs NO escaping at all, so any quote/backslash/space survives intact.
        """
        import base64
        b64 = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
        return self._base + [self.target,
                             "powershell -NoProfile -NonInteractive -EncodedCommand {}".format(b64)]

    def _scp_base(self):
        base = ["scp", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        if self._key:
            base += ["-i", self._key]
        if self._port:
            base += ["-P", str(self._port)]
        return base + self._extra

    def _start_snippet(self, argv, log_path):
        """Launch the job DETACHED via WMI Win32_Process.Create and PRINT its PID.

        Start-Process -PassThru WITHOUT -Wait dies when the transient OpenSSH PowerShell session ends
        (the child is tied to that session), so background jobs never actually ran — PID returned, log
        empty, ready-file never written. Win32_Process.Create starts a process with NO parent session,
        surviving the ssh disconnect. It has no redirect params, so stdout/stderr are redirected by the
        shell (cmd /c ... > log 2> err). Paths use forward slashes (accepted by Windows) to avoid any
        backslash mangling; the whole snippet is transported via -EncodedCommand, so quotes are safe.
        """
        pyexe = self._python
        def q(a):
            a = str(a)
            return '"{}"'.format(a) if (" " in a or a == "") else a
        # map python3 -> the configured interpreter; keep every other arg as-is
        mapped = [pyexe if (i == 0 and a in ("python3", "python")) else str(a) for i, a in enumerate(argv)]
        cmdline = " ".join(q(a) for a in mapped)
        redir = ' > "{}" 2> "{}"'.format(log_path, log_path + ".err")
        full = "cmd /c " + cmdline + redir
        # single-quote for the PowerShell hashtable value; double embedded single quotes
        full_ps = full.replace("'", "''")
        return ("$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
                "-Arguments @{{ CommandLine = '{}' }}; $r.ProcessId").format(full_ps)

    def run(self, argv, timeout=None):
        return run_cmd(self._pwsh(self._win_cmdline(argv)), timeout=timeout)

    def start_background(self, argv, log_path=None, name=""):
        log = log_path or "%TEMP%\\labbg_{}.log".format(int(time.time()))
        r = run_cmd(self._pwsh(self._start_snippet(argv, log)), timeout=30)
        pid = None
        if r.ok:
            tail = (r.stdout or "").strip().splitlines()
            pid = tail[-1].strip() if tail else None
        return BgJob(self, pid, target=self.target, log_path=log, name=name)

    def wait_background(self, job, timeout=None):
        end = time.time() + (timeout if timeout is not None else 0)
        while True:
            chk = run_cmd(self._pwsh("if (Get-Process -Id {} -ErrorAction SilentlyContinue) "
                                     "{{'UP'}} else {{'GONE'}}".format(job.pid)), timeout=15)
            if "GONE" in (chk.stdout or ""):
                return 0
            if timeout is not None and time.time() >= end:
                return None
            time.sleep(1)

    def stop_background(self, job, grace=3.0):
        run_cmd(self._pwsh("Stop-Process -Id {} -Force -ErrorAction SilentlyContinue".format(job.pid)),
                timeout=15)
        return 0

    def fetch(self, remote_path, local_path):
        r = run_cmd(self._scp_base() + ["{}:{}".format(self.target, remote_path.replace("\\", "/")), local_path], timeout=300)
        return r.ok

    def push(self, local_path, remote_path):
        r = run_cmd(self._scp_base() + [local_path, "{}:{}".format(self.target, remote_path.replace("\\", "/"))], timeout=300)
        return r.ok

    def mkdir(self, path):
        return run_cmd(self._pwsh("New-Item -ItemType Directory -Force -Path '{}' | Out-Null".format(path)),
                       timeout=30).ok

    def exists(self, path):
        r = run_cmd(self._pwsh("if (Test-Path '{}') {{'YES'}} else {{'NO'}}".format(path)), timeout=30)
        return "YES" in (r.stdout or "")

    def file_size(self, path):
        r = run_cmd(self._pwsh("if (Test-Path '{}') {{(Get-Item '{}').Length}} else {{-1}}".format(path, path)),
                    timeout=30)
        tail = (r.stdout or "").strip().splitlines()
        try:
            return int(tail[-1]) if tail else -1
        except ValueError:
            return -1


def make_runner(spec):
    """Build a Runner from a small dict, e.g. {"kind":"local"}, {"kind":"ssh","target":"lab@10.10.10.11",
    "key":"~/.ssh/id_lab"} or {"kind":"windows","target":"lab@10.10.10.20"} for NB2. Unknown -> local."""
    spec = spec or {}
    kind = spec.get("kind")
    if kind == "windows" and spec.get("target"):
        return WindowsRunner(os.path.expanduser(spec["target"]), key=spec.get("key"),
                             port=spec.get("port"), extra_opts=spec.get("opts"),
                             python=spec.get("python", "python"))
    if kind == "ssh" and spec.get("target"):
        return SSHRunner(os.path.expanduser(spec["target"]), key=spec.get("key"),
                         port=spec.get("port"), extra_opts=spec.get("opts"))
    return LocalRunner()


# --------------------------------------------------------------------------- misc

def disk_free_bytes(path):
    """Free bytes on the filesystem holding `path` (preflight checks NB4 has room for the PCAP)."""
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def print_banner(tool):
    """One-line banner every CLI prints, so logs record exactly which automation version ran."""
    print("{} ({})".format(tool, TOOL_VERSION), file=sys.stderr)
