import os
import shutil
from unittest.mock import patch

from common import encoded, read_json, sha
from recovery import Guard, checkpoint_active, halt, resume
from test_support import RuntimeCase


class RecoveryTests(RuntimeCase):
    def test_changed_workspace_cannot_hide_corrupt_prior_checkpoint_on_resume(self):
        guard = self.guard()
        result = guard.checkpoint(state={"owned_jobs": ["offline-owned-job"]})
        halt(self.home, "codex", "test_limit")
        before = (guard.runtime / "latest.json").read_bytes()
        artifact = guard.snapshots / result["snapshot"] / "staged.patch"
        artifact.write_bytes(b"corrupt-old-state")
        self.write("source.txt", "different dirty content\n")
        for operation in (lambda: resume(self.home, True), lambda: guard.checkpoint()):
            with self.assertRaises(ValueError):
                operation()
            self.assertTrue(self.home.halted())
            self.assertEqual((guard.runtime / "latest.json").read_bytes(), before)
            self.assertEqual(artifact.read_bytes(), b"corrupt-old-state")

    def test_valid_changed_workspace_reconciles_without_replay(self):
        guard = self.guard()
        first = guard.checkpoint(state={"owned_jobs": ["job-to-inspect"]})
        halt(self.home, "codex", "test_limit")
        self.write("source.txt", "owner-edited-current\n")
        result = resume(self.home, True)
        self.assertFalse(result["replayed"])
        self.assertTrue(result["reconciliation"][0]["unstaged_changed"])
        self.assertEqual(result["reconciliation"][0]["saved_snapshot"], first["snapshot"])
        self.assertEqual(result["reconciliation"][0]["owned_jobs"], ["job-to-inspect"])
        self.assertEqual((self.root / "source.txt").read_text(), "owner-edited-current\n")

    def test_empty_pointer_blocks_new_checkpoint(self):
        guard = self.guard()
        guard.checkpoint()
        (guard.runtime / "latest.json").write_text("{}")
        self.write("source.txt", "new content")
        with self.assertRaises(ValueError):
            guard.checkpoint()

    def guard(self, task="task-one"):
        return Guard(self.home, self.root, task)

    def test_dirty_staged_unstaged_untracked_and_no_replay(self):
        self.write("source.txt", "staged\n")
        self.git("add", "source.txt")
        self.write("source.txt", "unstaged\n")
        self.write("new file.txt", "new content\n")
        guard = self.guard()
        before = self.git("status", "--porcelain=v1", "-z")
        result = guard.checkpoint(state={"objective": "offline test", "jobs": []})
        folder = guard.snapshots / result["snapshot"]
        self.assertIn(b"+staged", (folder / "staged.patch").read_bytes())
        self.assertIn(b"+unstaged", (folder / "unstaged.patch").read_bytes())
        manifest = guard.verify_snapshot(folder)
        self.assertEqual(
            (folder / manifest["untracked"][0]["artifact"]).read_bytes(),
            b"new content\n",
        )
        self.assertTrue(guard.status()["workspace_matches"])
        halt(self.home, "codex", "test_limit")
        with self.assertRaises(ValueError):
            resume(self.home)
        self.assertFalse(resume(self.home, True)["replayed"])
        self.assertEqual(self.git("status", "--porcelain=v1", "-z"), before)
        self.assertEqual(self.git("show", ":source.txt"), b"staged\n")
        self.assertEqual((self.root / "source.txt").read_bytes(), b"unstaged\n")

    def test_unchanged_checkpoint_deduplicates_and_dirty_content_detected(self):
        guard = self.guard()
        self.write("source.txt", "first\n")
        first = guard.checkpoint()
        self.assertEqual(guard.checkpoint()["snapshot"], first["snapshot"])
        self.write("source.txt", "second\n")
        self.assertFalse(guard.status()["workspace_matches"])
        self.assertNotEqual(guard.checkpoint()["snapshot"], first["snapshot"])

    def test_task_and_worktree_isolation(self):
        one, two = self.guard("one"), self.guard("two")
        one.checkpoint()
        self.assertNotEqual(one.runtime, two.runtime)
        self.assertFalse(two.status()["latest"])
        linked = self.base / "linked"
        self.git("worktree", "add", "--detach", str(linked))
        other = Guard(self.home, linked, "one")
        self.assertNotEqual(one.runtime, other.runtime)
        other.checkpoint()
        pointer = read_json(one.runtime / "latest.json")
        target = other.snapshots / pointer["snapshot"]
        shutil.copytree(one.snapshots / pointer["snapshot"], target)
        (other.runtime / "latest.json").write_bytes(encoded(pointer))
        with self.assertRaises(ValueError):
            other.status()

    def test_corrupt_artifact_blocks_status_checkpoint_and_resume(self):
        guard = self.guard()
        result = guard.checkpoint()
        (guard.snapshots / result["snapshot"] / "staged.patch").write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            guard.status()
        with self.assertRaises(ValueError):
            guard.checkpoint()
        halted = halt(self.home, "codex", "test_limit")
        self.assertFalse(halted["tasks"][0]["checkpointed"])
        with self.assertRaises(ValueError):
            resume(self.home, True)
        self.assertTrue(self.home.halted())

    def test_snapshot_unexpected_file_and_pointer_traversal_rejected(self):
        guard = self.guard()
        result = guard.checkpoint()
        (guard.snapshots / result["snapshot"] / "extra").write_bytes(b"x")
        with self.assertRaises(ValueError):
            guard.status()
        (guard.runtime / "latest.json").write_bytes(
            encoded({"snapshot": "../../outside"})
        )
        with self.assertRaises(ValueError):
            guard.status()

    def test_sensitive_paths_content_history_and_binary_are_not_saved(self):
        secret = b"sk-" + b"synthetic" * 5
        self.write("history.txt", b"old=" + secret + b"\n")
        self.git("add", "history.txt")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "history fixture")
        self.write("history.txt", "safe now\n")
        self.write("source.txt", b"setting=" + secret + b"\n")
        self.git("add", "source.txt")
        self.write("source.txt", "safe worktree\n")
        self.write(".env", secret)
        self.write("plain.txt", b"password = 'synthetic-private-value'\n")
        self.write("binary.bin", b"\0opaque")
        self.write("safe.txt", "retained\n")
        self.write("ignored.txt", secret)
        self.write(".gitignore", "ignored.txt\n")
        guard = self.guard()
        result = guard.checkpoint()
        self.assertFalse(result["complete"])
        for file in guard.runtime.rglob("*"):
            if file.is_file():
                self.assertNotIn(secret, file.read_bytes())
                self.assertNotIn(b"synthetic-private-value", file.read_bytes())
                self.assertNotIn(b"\0opaque", file.read_bytes())
        manifest = guard.verify_snapshot(guard.snapshots / result["snapshot"])
        self.assertEqual(manifest["tracked_paths"], [])
        self.assertEqual(
            {e["path"] for e in manifest["untracked"]}, {"safe.txt", ".gitignore"}
        )

    def test_symlinks_hardlinks_and_unmerged_sources_skipped(self):
        outside = self.base / "outside"
        outside.write_text("outside private\n")
        (self.root / "linked.txt").symlink_to(outside)
        os.link(outside, self.root / "hardlinked.txt")
        self.git("add", "linked.txt")
        manifest, files = self.guard().collect()
        self.assertFalse(manifest["complete"])
        self.assertEqual(manifest["tracked_paths"], [])
        self.assertNotIn(b"outside private", b"".join(files.values()))

    def test_retention_and_storage_bounds(self):
        guard = self.guard()
        with patch("recovery.KEEP_SNAPSHOTS", 2):
            for value in range(4):
                self.write("source.txt", f"value {value}\n")
                guard.checkpoint()
        self.assertEqual(len(list(guard.snapshots.iterdir())), 2)
        self.write("source.txt", "next\n")
        before = (guard.runtime / "latest.json").read_bytes()
        with patch("recovery.MAX_RECOVERY_BYTES", 1), self.assertRaises(ValueError):
            guard.checkpoint()
        self.assertEqual((guard.runtime / "latest.json").read_bytes(), before)

    def test_path_state_and_task_bounds(self):
        guard = self.guard()
        self.write("one.txt", "one")
        self.write("two.txt", "two")
        with patch("recovery.MAX_PATHS", 1), self.assertRaises(ValueError):
            guard.checkpoint()
        with self.assertRaises(ValueError):
            guard.checkpoint(state={"value": "x" * 16384})
        with self.assertRaises(ValueError):
            guard.checkpoint(state={"api_key": "synthetic"})
        with patch("recovery.MAX_RECOVERY_TASKS", 1), self.assertRaises(ValueError):
            self.guard("another")

    def test_active_registry_corruption_and_bound_fail_closed(self):
        self.guard().checkpoint()
        with patch("recovery.MAX_ACTIVE_TASKS", 1), self.assertRaises(ValueError):
            self.guard("other").checkpoint()
        self.state("active-tasks.json", {"version": 1, "tasks": []})
        with self.assertRaises(ValueError):
            checkpoint_active(self.home, "test")
        with self.assertRaises(ValueError):
            halt(self.home, "codex", "test")
        self.assertTrue(self.home.halted())

    def test_unborn_and_deleted_file_checkpoint(self):
        (self.root / "source.txt").unlink()
        guard = self.guard()
        manifest, files = guard.collect()
        self.assertIn(b"-base", files["unstaged.patch"])
        new = self.base / "unborn"
        new.mkdir()
        old = self.root
        self.root = new
        self.git("init", "-q")
        self.write("first.txt", "first\n")
        self.git("add", "first.txt")
        result = Guard(self.home, new, "new").checkpoint()
        self.assertIsNone(result["head"])
        self.root = old

    def test_concurrent_dirty_change_does_not_commit_snapshot(self):
        guard = self.guard()
        first, files = guard.collect()
        changed = dict(first, status_sha256=sha(b"different"))
        with patch.object(
            guard, "collect", side_effect=[(first, files), (changed, files)]
        ):
            with self.assertRaises(ValueError):
                guard.checkpoint()
        self.assertFalse((guard.runtime / "latest.json").exists())

    def test_halt_is_idempotent_and_never_replays(self):
        self.guard().checkpoint()
        halt(self.home, "codex", "test_limit")
        before = (self.home.path / "halt.json").read_bytes()
        with patch(
            "recovery.checkpoint_active", side_effect=AssertionError("no repeat sweep")
        ):
            self.assertTrue(halt(self.home, "typesafe", "test_limit")["already_halted"])
        self.assertEqual((self.home.path / "halt.json").read_bytes(), before)
