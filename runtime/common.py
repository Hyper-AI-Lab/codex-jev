"""Private local persistence; Python 3.11 standard library only."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import selectors
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
JSON_LIMIT = 1024 * 1024
MAX_SESSIONS = 128
MAX_ACTIVE_TASKS = 64


def identifier(value):
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 200
        and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    )


def task_registry(value):
    if not value:
        return {"version": 1, "tasks": {}}
    tasks = value.get("tasks")
    if (
        value.get("version") != 1
        or not isinstance(tasks, dict)
        or len(tasks) > MAX_ACTIVE_TASKS
    ):
        raise ValueError("Invalid or oversized active task registry")
    for key, item in tasks.items():
        if (
            not isinstance(key, str)
            or len(key) != 129
            or not isinstance(item, dict)
            or not identifier(item.get("task"))
            or not isinstance(item.get("root"), str)
            or not Path(item["root"]).is_absolute()
            or len(item["root"]) > 4096
            or not isinstance(item.get("updated_at"), str)
        ):
            raise ValueError("Invalid active task entry")
    return value


def encoded(value):
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n"
    ).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def no_symlinks(path):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("Symlink in private state path")
    return path


def private_directory(path):
    path = no_symlinks(path)
    if not path.parent.exists():
        private_directory(path.parent)
    path.mkdir(mode=0o700, exist_ok=True)
    if not path.is_dir():
        raise ValueError("Expected directory")
    path.chmod(0o700)


def read_bytes(path, limit=JSON_LIMIT):
    path = no_symlinks(path)
    if not path.exists():
        return b""
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected regular file")
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise ValueError("Input exceeds size limit")
    return result


def read_json(path):
    data = read_bytes(path)
    value = json.loads(data) if data else {}
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object")
    return value


def atomic_write(path, data):
    path = no_symlinks(path)
    if path.exists() and not path.is_file():
        raise ValueError("Expected regular output file")
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.chmod(temporary, 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_transaction(changes):
    """Rollback caught errors from memory only; never persist raw preimages."""
    originals = {path: (path.exists(), read_bytes(path)) for path in changes}
    written = []
    try:
        for path, data in changes.items():
            existed, before = originals[path]
            if existed and data == before:
                continue
            written.append(path)
            atomic_write(path, data)
    except Exception:
        for path in reversed(written):
            existed, before = originals[path]
            current = read_bytes(path)
            if current == before and (existed or not path.exists()):
                continue
            if current != changes[path]:
                raise ValueError(
                    "Concurrent owner change preserved; inspect pending installation"
                ) from None
            if existed:
                atomic_write(path, before)
            else:
                no_symlinks(path).unlink(missing_ok=True)
        raise


@contextlib.contextmanager
def locked(path, timeout=5):
    path = no_symlinks(path)
    descriptor = os.open(
        path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "r+b") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Invalid lock file")
        os.chmod(path, 0o600)
        if os.name == "nt":
            import msvcrt

            if not os.fstat(stream.fileno()).st_size:
                stream.write(b"0")
                stream.flush()

            def lock():
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)

            def unlock():
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            def lock():
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)

            def unlock():
                fcntl.flock(stream, fcntl.LOCK_UN)

        deadline = time.monotonic() + timeout
        while True:
            stream.seek(0)
            try:
                lock()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Private state is busy") from None
                time.sleep(0.02)
        try:
            yield
        finally:
            stream.seek(0)
            unlock()


def git(root, *args, check=True, limit=MAX_BYTES, input_data=None):
    # Host hooks must not inherit GIT_DIR/GIT_WORK_TREE from an unrelated shell.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    command = ["git", "--literal-pathspecs", "-C", str(root), *args]
    # Bound output while streaming, including diffs of unexpectedly huge blobs.
    if input_data is not None and (not isinstance(input_data, bytes) or len(input_data) > JSON_LIMIT):
        raise ValueError("Git input exceeds capture budget")
    # An anonymous file avoids stdin/stdout pipe deadlock for batched blobs.
    with contextlib.ExitStack() as stack:
        source = stack.enter_context(tempfile.TemporaryFile()) if input_data is not None else subprocess.DEVNULL
        if input_data is not None:
            source.write(input_data)
            source.seek(0)
        process = stack.enter_context(subprocess.Popen(
            command, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env))
        try:
            chunks, size, deadline = [], 0, time.monotonic() + 10
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError("Git capture timed out")
                    chunk = os.read(
                        process.stdout.fileno(), min(65536, limit - size + 1)
                    )
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise ValueError("Git output exceeds capture budget")
                    chunks.append(chunk)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if code and check:
                raise subprocess.CalledProcessError(code, ["git", "<private capture>"])
            return b"".join(chunks) if not code else None
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def git_root(path):
    candidate = Path(path).expanduser().resolve(strict=True)
    if not candidate.is_dir():
        raise ValueError("Workspace is not a directory")
    raw = git(candidate, "rev-parse", "--show-toplevel", check=False)
    if not raw:
        raise ValueError("Workspace is not a Git worktree")
    root = Path(os.fsdecode(raw).strip()).resolve(strict=True)
    if root in {Path("/"), Path("/root"), Path.home().resolve()}:
        raise ValueError("Broad home/root workspace is forbidden")
    if not candidate.is_relative_to(root):
        raise ValueError("Workspace root mismatch")
    return root


class Home:
    def __init__(self, codex_home=None):
        self.codex = no_symlinks(
            Path(
                codex_home or os.environ.get("CODEX_HOME", Path.home() / ".codex")
            ).expanduser()
        )
        self.path = self.codex / "jev-context"

    def ensure(self):
        probe = self.path
        while not probe.exists():
            probe = probe.parent
        if git(probe, "rev-parse", "--show-toplevel", check=False):
            raise ValueError("Recovery home must be outside Git repositories")
        private_directory(self.codex)
        private_directory(self.path)

    def lock(self):
        self.ensure()
        return locked(self.path / "runtime.lock")

    def halted(self):
        path = no_symlinks(self.path / "halt.json")
        if not path.exists():
            return False
        value = read_json(path)
        if not value or not all(key in value for key in ("provider", "reason", "at")):
            raise ValueError("Invalid halt marker; explicit recovery required")
        return True

    def registry(self):
        value = read_json(self.path / "authorized-workspaces.json")
        if not value:
            return {"version": 1, "sessions": {}, "roots": []}
        if (
            value.get("version") != 1
            or not isinstance(value.get("sessions"), dict)
            or not isinstance(value.get("roots"), list)
            or len(value["sessions"]) > MAX_SESSIONS
        ):
            raise ValueError("Invalid authorized workspace registry")
        for session, entry in value["sessions"].items():
            if (
                not identifier(session)
                or not isinstance(entry, dict)
                or not isinstance(entry.get("root"), str)
                or len(entry["root"]) > 4096
                or not Path(entry["root"]).is_absolute()
                or not isinstance(entry.get("updated_at"), str)
            ):
                raise ValueError("Invalid authorized workspace entry")
        if value["roots"] != sorted(
            {item["root"] for item in value["sessions"].values()}
        ):
            raise ValueError("Workspace registry roots do not match sessions")
        return value

    def register(self, root, session_id):
        if not identifier(session_id):
            raise ValueError("Invalid host session identifier")
        root = git_root(root)
        if self.path.is_relative_to(root):
            raise ValueError("Recovery home is inside workspace")
        with self.lock():
            registry = self.registry()
            if (
                session_id not in registry["sessions"]
                and len(registry["sessions"]) >= MAX_SESSIONS
            ):
                raise ValueError("Workspace registry full; explicit cleanup required")
            registry["sessions"][session_id] = {"root": str(root), "updated_at": now()}
            registry["roots"] = sorted(
                {item["root"] for item in registry["sessions"].values()}
            )
            data = encoded(registry)
            if len(data) > JSON_LIMIT:
                raise ValueError("Workspace registry exceeds storage budget")
            atomic_write(self.path / "authorized-workspaces.json", data)
        return root

    def log_callback(self, event, session_id, result):
        # Never retain raw hook payloads, commands, prompts, transcripts or results.
        with self.lock():
            path = self.path / "callbacks.json"
            value = read_json(path)
            events = value.get("events", [])[-255:]
            events.append(
                {
                    "event": event,
                    "session_hash": sha(str(session_id).encode()),
                    "at": now(),
                    "result": result,
                }
            )
            atomic_write(path, encoded({"version": 1, "events": events}))
