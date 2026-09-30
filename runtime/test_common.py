import os
from unittest.mock import patch

from common import Home, atomic_write, encoded, git, read_bytes, write_transaction
from test_support import RuntimeCase


class CommonTests(RuntimeCase):
    def test_symlink_and_fifo_denied(self):
        target = self.home.path / "target"
        target.write_bytes(b"private")
        link = self.home.path / "link"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            read_bytes(link)
        fifo = self.home.path / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            read_bytes(fifo)
        with self.assertRaises(ValueError):
            atomic_write(link, b"overwritten")
        self.assertEqual(target.read_bytes(), b"private")

    def test_state_home_cannot_be_in_git(self):
        with self.assertRaises(ValueError):
            Home(self.root / "private").ensure()

    def test_atomic_files_private(self):
        target = self.home.path / "private.json"
        atomic_write(target, encoded({"ok": True}))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.home.path.stat().st_mode & 0o777, 0o700)

    def test_git_output_bounded(self):
        with self.assertRaises(ValueError):
            git(self.root, "show", "HEAD:source.txt", limit=2)

    def test_git_environment_isolation(self):
        with patch.dict(
            os.environ, {"GIT_DIR": "/missing", "GIT_WORK_TREE": "/missing"}
        ):
            self.assertEqual(git(self.root, "show", "HEAD:source.txt"), b"base\n")

    def test_registry_rejects_capacity_and_corruption(self):
        with patch("common.MAX_SESSIONS", 1):
            self.home.register(self.root, "one")
            self.home.register(self.root, "one")
            before = (self.home.path / "authorized-workspaces.json").read_bytes()
            with self.assertRaises(ValueError):
                self.home.register(self.root, "two")
            self.assertEqual(
                (self.home.path / "authorized-workspaces.json").read_bytes(), before
            )
        value = self.home.registry()
        value["roots"].append("/unauthorized")
        self.state("authorized-workspaces.json", value)
        with self.assertRaises(ValueError):
            self.home.registry()

    def test_transaction_failure_rolls_back_without_disk_backup(self):
        first = self.native("one", "original")
        second = self.home.codex / "two"

        def failing(path, data):
            if path == second:
                raise OSError("synthetic")
            atomic_write(path, data)

        with (
            patch("common.atomic_write", side_effect=failing),
            self.assertRaises(OSError),
        ):
            write_transaction({first: b"change", second: b"new"})
        self.assertEqual(first.read_bytes(), b"original")
        self.assertFalse(second.exists())

    def test_transaction_preserves_concurrent_edit(self):
        first = self.native("one", "original")
        second = self.home.codex / "two"

        def racing(path, data):
            if path == second:
                first.write_bytes(b"owner edit")
                raise OSError("synthetic")
            atomic_write(path, data)

        with (
            patch("common.atomic_write", side_effect=racing),
            self.assertRaises(ValueError),
        ):
            write_transaction({first: b"change", second: b"new"})
        self.assertEqual(first.read_bytes(), b"owner edit")
