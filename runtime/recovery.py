"""Adapted from Cyber-Team .codex/quota_guard.py; never replays or kills jobs.

Separate index/worktree patches, private atomic snapshots, artifact verification,
and verified retention are retained from that guard. State now lives outside Git.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from common import (
    JSON_LIMIT,
    MAX_ACTIVE_TASKS,
    MAX_BYTES,
    Home,
    atomic_write,
    encoded,
    git,
    git_root,
    locked,
)
from common import no_symlinks, now, private_directory, read_bytes, read_json, sha
from common import identifier, task_registry

KEEP_SNAPSHOTS = 8
SNAPSHOT_NAME = re.compile(r"^[0-9a-f]{64}$")
MAX_PATHS = 4096
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_RECOVERY_BYTES = 256 * 1024 * 1024
MAX_STORAGE_ENTRIES = 32768
MAX_RECOVERY_TASKS = 512
SENSITIVE = re.compile(
    rb"-----BEGIN [^-]*PRIVATE KEY-----|"
    rb"\b(?:sk-[A-Za-z0-9_-]{12,}|tsk[-_][A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9_]{15,}|"
    rb"github_pat_[A-Za-z0-9_]{15,}|AIza[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b|"
    rb"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|"
    rb"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)"
    rb"[\w.-]*[\"']?\s*[:=]\s*\S|https?://[^\s/@]+:[^\s/@]+@",
    re.IGNORECASE,
)


def sensitive(data):
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return b"\0" in data or bool(SENSITIVE.search(data))


def storage_usage(base):
    total, entries, tasks = 0, 0, 0
    if not base.exists():
        return total, tasks
    no_symlinks(base)
    for parent, dirs, files in os.walk(base, followlinks=False):
        for name in dirs + files:
            path = no_symlinks(Path(parent) / name)
            info = path.lstat()
            entries += 1
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError("Non-regular recovery storage entry")
            if path.parent.name == "tasks" and path.is_dir():
                tasks += 1
            if (
                total > MAX_RECOVERY_BYTES
                or entries > MAX_STORAGE_ENTRIES
                or tasks > MAX_RECOVERY_TASKS
            ):
                raise ValueError(
                    "Recovery storage budget exhausted; explicit cleanup required"
                )
    return total, tasks


def excluded(name):
    parts = Path(name).parts
    base = parts[-1].lower() if parts else ""
    return (
        name in {".codex/task_state.json", ".codex/state_checkpoint.md"}
        or name.startswith((".codex/runtime/", ".codex/checkpoints/"))
        or any(
            p.lower()
            in {
                "backups",
                "secrets",
                "credentials",
                ".ssh",
                ".gnupg",
                ".git",
                ".aws",
                ".kube",
                ".codex",
                "node_modules",
                ".venv",
                ".venv-quality",
            }
            for p in parts
        )
        or base.startswith(".env")
        or base.endswith(
            (
                ".env",
                ".pem",
                ".key",
                ".p12",
                ".pfx",
                ".db",
                ".sqlite",
                ".sqlite3",
                ".dump",
            )
        )
        or base
        in {
            "auth.json",
            "credentials.json",
            "application_default_credentials.json",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "id_rsa",
            "id_ed25519",
        }
        or any(
            re.search(
                r"(^|[._-])(secret|credential|token|password)s?([._-]|$)", p.lower()
            )
            for p in parts
        )
        or any(ord(c) < 32 for c in name)
        or sensitive(os.fsencode(name))
    )


def batch_blobs(root, identifiers):
    identifiers = sorted(set(identifiers))
    if not identifiers:
        return {}
    if any(not re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", value) for value in identifiers):
        raise ValueError("Invalid Git blob identity")
    sizes = git(root, "cat-file", "--batch-check", input_data=b"\n".join(identifiers) + b"\n")
    eligible, total = [], 0
    for expected, line in zip(identifiers, sizes.splitlines(), strict=True):
        fields = line.split()
        if len(fields) != 3 or fields[0] != expected or fields[1] != b"blob":
            raise ValueError("Git blob metadata changed")
        size = int(fields[2])
        if 0 <= size <= MAX_SOURCE_BYTES:
            total += size
            eligible.append(expected)
    if total > MAX_BYTES * 2:
        raise ValueError("Source inspection budget exceeded")
    if not eligible:
        return {}
    raw = git(root, "cat-file", "--batch", input_data=b"\n".join(eligible) + b"\n", limit=MAX_BYTES * 2 + JSON_LIMIT)
    result, offset = {}, 0
    for expected in eligible:
        end = raw.index(b"\n", offset)
        fields = raw[offset:end].split()
        if len(fields) != 3 or fields[0] != expected or fields[1] != b"blob":
            raise ValueError("Git blob response mismatch")
        size = int(fields[2])
        if not 0 <= size <= MAX_SOURCE_BYTES:
            raise ValueError("Invalid Git blob size")
        offset = end + 1
        result[expected] = raw[offset:offset + size]
        if len(result[expected]) != size or raw[offset + size:offset + size + 1] != b"\n":
            raise ValueError("Truncated Git blob")
        offset += size + 1
    if offset != len(raw):
        raise ValueError("Unexpected Git blob data")
    return result


class Guard:
    def __init__(self, home: Home, root, task):
        self.home = home
        self.root = git_root(root)
        if not identifier(task):
            raise ValueError("Invalid task identifier")
        self.task = task
        home.ensure()
        if home.path.is_relative_to(self.root):
            raise ValueError("Recovery storage must be outside workspace")
        self.git_dir = os.fsdecode(self.git("rev-parse", "--absolute-git-dir")).strip()
        self.worktree_id = sha(
            encoded({"root": str(self.root), "git_dir": self.git_dir})
        )
        self.task_id = sha(task.encode())
        self.runtime = (
            home.path / "recovery" / self.worktree_id / "tasks" / self.task_id
        )
        self.snapshots = self.runtime / "checkpoints"
        no_symlinks(self.runtime)
        if not self.runtime.exists():
            with locked(home.path / "recovery.lock"):
                _, tasks = storage_usage(home.path / "recovery")
                if tasks >= MAX_RECOVERY_TASKS:
                    raise ValueError("Recovery history limit reached; explicit cleanup required")
                private_directory(self.snapshots)
        else:
            private_directory(self.snapshots)

    def git(self, *args):
        return git(self.root, *args)

    def locked(self):
        return locked(self.runtime / "guard.lock")

    def head(self):
        value = git(self.root, "rev-parse", "--verify", "HEAD", check=False)
        return os.fsdecode(value).strip() if value else None

    def collect(self):
        head = self.head()
        branch = git(
            self.root, "symbolic-ref", "--quiet", "--short", "HEAD", check=False
        )
        branch = os.fsdecode(branch).strip() if branch else "HEAD"
        status = self.git("status", "--porcelain=v1", "-z", "--untracked-files=all")
        tracked = sorted(
            set(
                self.git("diff", "--no-renames", "--name-only", "-z").split(b"\0")
                + self.git(
                    "diff", "--cached", "--no-renames", "--name-only", "-z"
                ).split(b"\0")
            )
        )
        untracked = self.git("ls-files", "--others", "--exclude-standard", "-z").split(
            b"\0"
        )
        if len(tracked) + len(untracked) > MAX_PATHS + 2:
            raise ValueError("Workspace path count exceeds capture budget")
        eligible_names = {raw for raw in tracked if raw and not excluded(os.fsdecode(raw))}
        index, history = {}, {}
        for entry in self.git("ls-files", "--stage", "-z").split(b"\0"):
            if entry:
                header, name = entry.split(b"\t", 1)
                if name in eligible_names:
                    index.setdefault(name, []).append(header.split())
        if head:
            for entry in self.git("ls-tree", "-rz", "HEAD").split(b"\0"):
                if entry:
                    header, name = entry.split(b"\t", 1)
                    fields = header.split()
                    if name in eligible_names and fields[1] == b"blob":
                        history[name] = fields[2]
        blob_ids = [row[1] for rows in index.values() for row in rows
                    if row[2] == b"0" and row[0] in (b"100644", b"100755")] + list(history.values())
        blobs = batch_blobs(self.root, blob_ids)
        skipped, paths = [], []
        scanned = 0
        for raw in tracked:
            if not raw:
                continue
            name = os.fsdecode(raw)
            if excluded(name):
                skipped.append(
                    {"path_hash": sha(raw), "reason": "sensitive or recovery path"}
                )
            else:
                try:
                    current = no_symlinks(self.root / name)
                    if current.exists() and (
                        not current.is_file() or current.stat().st_nlink != 1
                    ):
                        raise ValueError("Non-regular source")
                    if any(
                        row[0] not in (b"100644", b"100755") or row[2] != b"0"
                        for row in index.get(raw, [])
                    ):
                        raise ValueError("Unmerged or special source")
                    sources = [read_bytes(current, MAX_SOURCE_BYTES)]
                    ids = ([history[raw]] if raw in history else []) + [row[1] for row in index.get(raw, [])]
                    if any(value not in blobs for value in ids):
                        raise ValueError("Oversized Git blob")
                    sources.extend(blobs[value] for value in ids)
                    scanned += sum(map(len, sources))
                    if any(sensitive(data) for data in sources):
                        raise ValueError("Sensitive source")
                except ValueError:
                    skipped.append(
                        {
                            "path_hash": sha(raw),
                            "reason": "sensitive, binary, oversized or special source",
                        }
                    )
                    continue
                if scanned > MAX_BYTES * 2:
                    raise ValueError("Source inspection budget exceeded")
                paths.append(name)
        files = {}
        for label, flags in (("staged.patch", ["--cached"]), ("unstaged.patch", [])):
            patch = b""
            if paths:
                patch = self.git(
                    "diff",
                    "--binary",
                    "--no-renames",
                    "--no-ext-diff",
                    "--no-textconv",
                    *flags,
                    "--",
                    *paths,
                )
                if sensitive(patch):
                    raise ValueError("Sensitive patch detected during capture")
                if len(patch) > MAX_BYTES:
                    raise ValueError("Diff exceeds capture budget")
            files[label] = patch
        size = sum(len(value) for value in files.values())
        if size > MAX_BYTES:
            raise ValueError("Diff exceeds capture budget")
        entries = []
        for raw in sorted(untracked):
            if not raw:
                continue
            name = os.fsdecode(raw)
            path = self.root / name
            if excluded(name):
                skipped.append(
                    {"path_hash": sha(raw), "reason": "sensitive or recovery path"}
                )
                continue
            try:
                no_symlinks(path)
                if (
                    not path.is_file()
                    or path.stat().st_nlink != 1
                    or not path.resolve().is_relative_to(self.root)
                ):
                    raise ValueError("Non-regular source")
            except ValueError:
                skipped.append({"path": name, "reason": "symlink or non-regular file"})
                continue
            if (
                path.stat().st_size > MAX_SOURCE_BYTES
                or path.stat().st_size + size > MAX_BYTES
            ):
                skipped.append({"path": name, "reason": "capture budget"})
                continue
            data = read_bytes(path, MAX_BYTES - size)
            if sensitive(data):
                skipped.append(
                    {"path_hash": sha(raw), "reason": "sensitive or binary source"}
                )
                continue
            size += len(data)
            key = f"untracked/{len(entries):06d}"
            files[key] = data
            entries.append(
                {
                    "path": name,
                    "artifact": key,
                    "sha256": sha(data),
                    "mode": stat.S_IMODE(path.stat().st_mode),
                    "size": len(data),
                }
            )
        manifest = {
            "kind": "jev-workspace-checkpoint-v1",
            "root": str(self.root),
            "git_dir": self.git_dir,
            "worktree_id": self.worktree_id,
            "task": self.task,
            "task_id": self.task_id,
            "head": head,
            "branch": branch,
            "status_sha256": sha(status),
            "tracked_paths": paths,
            "untracked": entries,
            "artifacts": {
                key: {"sha256": sha(value), "size": len(value)}
                for key, value in files.items()
            },
            "excluded": skipped,
            "complete": not skipped,
        }
        manifest["fingerprint"] = sha(encoded(manifest))
        if len(encoded(manifest)) > JSON_LIMIT:
            raise ValueError("Manifest exceeds storage budget")
        if (
            self.head() != head
            or self.git("status", "--porcelain=v1", "-z", "--untracked-files=all")
            != status
        ):
            raise ValueError("Workspace changed during capture")
        return manifest, files

    def checkpoint(self, reason="manual", state=None):
        started, success = time.perf_counter(), False
        try:
            result = self._checkpoint(reason, state)
            success = True
            return result
        finally:
            try:
                from measurements import record

                record(self.home, kind="checkpoint", values={"duration_ms": (time.perf_counter() - started) * 1000,
                       "success": int(success)}, session=self.task)
            except Exception:
                pass

    def _checkpoint(self, reason="manual", state=None):
        if not identifier(reason) or sensitive(reason.encode()):
            raise ValueError("Invalid checkpoint reason")
        if state is not None and (
            not isinstance(state, dict)
            or len(encoded(state)) > 16384
            or sensitive(encoded(state))
        ):
            raise ValueError("Task state must be a bounded non-sensitive object")
        self.register_active()
        with self.locked(), ExitStack() as publication:
            # Preserve corrupt evidence even when the current worktree has changed.
            self.verify_latest()
            manifest, files = self.collect()
            # Porcelain alone misses content changes to an already-dirty file.
            second, _ = self.collect()
            if second != manifest:
                raise ValueError("Workspace changed during capture")
            publication.enter_context(locked(self.home.path / "recovery.lock"))
            folder = self.snapshots / manifest["fingerprint"]
            no_symlinks(folder)
            if not folder.exists():
                # Hold the shared budget lock only for publication, not Git reads.
                used, _ = storage_usage(self.home.path / "recovery")
                required = sum(map(len, files.values())) + len(encoded(manifest)) + 32768
                if used + required > MAX_RECOVERY_BYTES:
                    raise ValueError("Recovery storage budget exhausted; explicit cleanup required")
                temporary = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.snapshots))
                try:
                    for name, value in files.items():
                        destination = temporary / name
                        if destination.parent != temporary:
                            private_directory(destination.parent)
                        atomic_write(destination, value)
                    atomic_write(temporary / "manifest.json", encoded(manifest))
                    os.rename(temporary, folder)
                finally:
                    if temporary.exists():
                        shutil.rmtree(temporary)
            if self.verify_snapshot(folder) != manifest:
                raise ValueError("Existing snapshot does not match capture")
            folder.touch()
            if state is not None:
                atomic_write(self.runtime / "task_state.json", encoded(state))
            pointer = {
                "snapshot": folder.name,
                "head": manifest["head"],
                "branch": manifest["branch"],
                "captured_at": now(),
                "reason": reason,
                "complete": manifest["complete"],
                "root": str(self.root),
                "task": self.task,
            }
            atomic_write(self.runtime / "latest.json", encoded(pointer))
            notes = (
                "# Private Recovery Checkpoint\n\n"
                f"Captured: {pointer['captured_at']}\nSnapshot: {folder}\n"
                f"HEAD: {manifest['head']}\nComplete: {manifest['complete']}\n\n"
                "Honor the latest owner request. Read task_state.json, then run status with the same workspace/task.\n"
                "Compare actual HEAD, staged/unstaged files, tests and owned jobs; verify artifacts first.\n"
                "Patches are evidence, never automatically replayed. Reconcile external effects manually.\n"
                "Only explicitly authorized resume --acknowledge clears the shared halt.\n"
                "No model memory, processes, databases or ignored secrets are restored.\n"
            )
            atomic_write(self.runtime / "state_checkpoint.md", notes.encode())
            folders = sorted(
                (
                    p
                    for p in self.snapshots.iterdir()
                    if SNAPSHOT_NAME.fullmatch(p.name)
                    and p.is_dir()
                    and not p.is_symlink()
                ),
                key=lambda p: p.stat().st_mtime_ns,
                reverse=True,
            )
            for old in folders[KEEP_SNAPSHOTS:]:
                self.verify_snapshot(old)
                shutil.rmtree(old)
        return {**pointer, "recovery_dir": str(self.runtime)}

    def close_session(self):
        with self.home.lock():
            path = self.home.path / "active-tasks.json"
            active = task_registry(read_json(path))
            active["tasks"].pop(self.worktree_id + ":" + self.task_id, None)
            atomic_write(path, encoded(active))
            registry = self.home.registry()
            entry = registry["sessions"].get(self.task)
            if entry and entry["root"] == str(self.root):
                registry["sessions"].pop(self.task)
                registry["roots"] = sorted({item["root"] for item in registry["sessions"].values()})
                atomic_write(self.home.path / "authorized-workspaces.json", encoded(registry))
            with locked(self.home.path / "recovery.lock"):
                atomic_write(self.runtime / "closed.json", encoded({"ended_at": now(), "history_preserved": True}))

    def register_active(self):
        with self.home.lock():
            path = self.home.path / "active-tasks.json"
            active = task_registry(read_json(path))
            key = self.worktree_id + ":" + self.task_id
            if key not in active["tasks"] and len(active["tasks"]) >= MAX_ACTIVE_TASKS:
                raise ValueError("Active task registry full; explicit cleanup required")
            active["tasks"][key] = {
                "root": str(self.root),
                "task": self.task,
                "updated_at": now(),
            }
            if len(encoded(active)) > JSON_LIMIT:
                raise ValueError("Active task registry exceeds storage budget")
            atomic_write(path, encoded(active))

    @staticmethod
    def verify_snapshot(folder):
        no_symlinks(folder)
        if not SNAPSHOT_NAME.fullmatch(folder.name):
            raise ValueError("Invalid snapshot directory")
        manifest = read_json(folder / "manifest.json")
        identity = {
            key: value for key, value in manifest.items() if key != "fingerprint"
        }
        if (
            manifest.get("kind") != "jev-workspace-checkpoint-v1"
            or manifest.get("fingerprint") != folder.name
            or sha(encoded(identity)) != folder.name
        ):
            raise ValueError("Snapshot identity does not verify")
        expected, total = {"manifest.json"}, 0
        if not isinstance(manifest.get("artifacts"), dict) or not {
            "staged.patch",
            "unstaged.patch",
        }.issubset(manifest["artifacts"]):
            raise ValueError("Missing patch metadata")
        for name, metadata in manifest["artifacts"].items():
            if name not in {"staged.patch", "unstaged.patch"} and not re.fullmatch(
                r"untracked/\d{6}", name
            ):
                raise ValueError("Invalid snapshot artifact path")
            artifact = no_symlinks(folder / name)
            if not artifact.is_file():
                raise ValueError("Missing artifact")
            if (
                not isinstance(metadata, dict)
                or type(metadata.get("size")) is not int
                or not 0 <= metadata["size"] <= MAX_BYTES
            ):
                raise ValueError("Invalid artifact metadata")
            if artifact.parent != folder:
                expected.add("untracked")
            expected.add(name)
            data = read_bytes(artifact, MAX_BYTES - total)
            total += len(data)
            if len(data) != metadata["size"] or sha(data) != metadata["sha256"]:
                raise ValueError("Snapshot artifact does not verify")
        if {p.relative_to(folder).as_posix() for p in folder.rglob("*")} != expected:
            raise ValueError("Snapshot contains unexpected or missing files")
        return manifest

    def verify_latest(self):
        path = self.runtime / "latest.json"
        pointer = read_json(path)
        if not pointer and path.exists():
            raise ValueError("Empty checkpoint pointer")
        if not pointer:
            return pointer, None
        if not isinstance(pointer.get("snapshot"), str) or not SNAPSHOT_NAME.fullmatch(pointer["snapshot"]):
            raise ValueError("Invalid checkpoint pointer")
        saved = self.verify_snapshot(self.snapshots / pointer["snapshot"])
        if (saved.get("root") != str(self.root) or saved.get("task") != self.task
                or saved.get("worktree_id") != self.worktree_id
                or saved.get("task_id") != self.task_id
                or pointer.get("root") != str(self.root) or pointer.get("task") != self.task
                or pointer.get("head") != saved.get("head")
                or pointer.get("complete") != saved.get("complete")):
            raise ValueError("Snapshot provenance mismatch")
        state = read_json(self.runtime / "task_state.json")
        if len(encoded(state)) > 16384 or sensitive(encoded(state)):
            raise ValueError("Invalid recovery task state")
        return pointer, saved

    def status(self):
        with self.locked():
            pointer, saved = self.verify_latest()
            manifest, _ = self.collect()
            state = read_json(self.runtime / "task_state.json")
            return {
                "halted": self.home.halted(),
                "latest": pointer,
                "head_matches": bool(pointer)
                and pointer.get("head") == manifest["head"],
                "workspace_matches": pointer.get("snapshot") == manifest["fingerprint"],
                "recovery_dir": str(self.runtime),
                "reconciliation": {
                    "previous_verified": saved is not None,
                    "saved_snapshot": pointer.get("snapshot"),
                    "current_fingerprint": manifest["fingerprint"],
                    "staged_changed": saved is not None and saved["artifacts"]["staged.patch"] != manifest["artifacts"]["staged.patch"],
                    "unstaged_changed": saved is not None and saved["artifacts"]["unstaged.patch"] != manifest["artifacts"]["unstaged.patch"],
                    "untracked_changed": saved is not None and saved["untracked"] != manifest["untracked"],
                    "owned_jobs": state.get("owned_jobs", state.get("jobs", [])),
                    "external_effects": "not_replayed; verify owned jobs and external state before continuation",
                },
            }


def checkpoint_active(home, reason):
    with home.lock():
        active = task_registry(read_json(home.path / "active-tasks.json"))["tasks"]
    results = []
    for key, task in active.items():
        try:
            guard = Guard(home, task["root"], task["task"])
            if key != guard.worktree_id + ":" + guard.task_id:
                raise ValueError("Active task identity mismatch")
            guard.checkpoint(reason)
            results.append({"id": key, "checkpointed": True})
        except Exception as exc:
            results.append(
                {"id": key, "checkpointed": False, "error": type(exc).__name__}
            )
    return results


def halt(home, provider, reason):
    if (
        provider not in {"codex", "typesafe"}
        or not identifier(reason)
        or sensitive(reason.encode())
    ):
        raise ValueError("Invalid halt metadata")
    with home.lock():
        if not home.halted():
            atomic_write(
                home.path / "halt.json",
                encoded({"provider": provider, "reason": reason, "at": now()}),
            )
        identity = sha(read_bytes(home.path / "halt.json"))
    # JS may create the marker first. Deduplicate completed sweeps, not markers.
    with locked(home.path / "halt-sweep.lock"):
        if (
            read_json(home.path / "halt-checkpoint.json").get("marker_sha256")
            == identity
        ):
            return {"halted": True, "tasks": [], "already_halted": True}
        results = checkpoint_active(home, "quota_halt")
        atomic_write(
            home.path / "halt-checkpoint.json",
            encoded({"marker_sha256": identity, "at": now()}),
        )
    return {"halted": True, "tasks": results}


def resume(home, acknowledge=False):
    if not acknowledge:
        raise ValueError(
            "Resume requires explicit owner authorization and --acknowledge"
        )
    with home.lock():
        previous = read_bytes(home.path / "halt.json")
        active = task_registry(read_json(home.path / "active-tasks.json"))["tasks"]
    verified = []
    # Validate every old pointer before any task may advance its checkpoint.
    for key, task in active.items():
        guard = Guard(home, task["root"], task["task"])
        if key != guard.worktree_id + ":" + guard.task_id:
            raise ValueError("Active task identity mismatch")
        checked = guard.status()
        if not checked["latest"]:
            raise ValueError("Active task has no recovery checkpoint; halt retained")
        verified.append({"id": key, **checked["reconciliation"]})
    results = checkpoint_active(home, "owner_authorized_resume_preflight")
    if any(not item["checkpointed"] for item in results):
        raise ValueError("Resume checkpoints failed; halt retained")
    with home.lock():
        if read_bytes(home.path / "halt.json") != previous:
            raise ValueError("Halt changed during resume; inspect before retrying")
        no_symlinks(home.path / "halt.json").unlink(missing_ok=True)
    return {"halted": False, "tasks": results, "reconciliation": verified, "replayed": False}
