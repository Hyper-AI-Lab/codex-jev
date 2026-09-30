"""Isolated, offline runtime fixtures. No user's Codex home is ever opened."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from common import Home, encoded, read_json


class RuntimeCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="jev-runtime-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.home = Home(self.base / "codex-home")
        self.home.ensure()
        self.git("init", "-q")
        self.git("config", "user.email", "offline@example.invalid")
        self.git("config", "user.name", "Offline Test")
        self.write("source.txt", "base\n")
        self.git("add", "source.txt")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture")

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
            GIT_TERMINAL_PROMPT="0",
        )
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            env=env,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def native(self, name, data):
        path = self.home.codex / name
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def state(self, name, value):
        path = self.home.path / name
        path.write_bytes(encoded(value))
        return path

    def read_state(self, name):
        return read_json(self.home.path / name)
