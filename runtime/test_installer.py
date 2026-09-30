import json
import os
import shlex
import shutil
import sys
import tomllib
from pathlib import Path
from unittest.mock import patch

from common import atomic_write, read_json
from installer import (
    CHECKOUT,
    DEFAULTS,
    EVENTS,
    MANAGE,
    install,
    uninstall,
    validate_config,
)
from test_support import RuntimeCase

ISOLATED_NODE = CHECKOUT / ".toolchain/node-v22.23.3-linux-x64/bin/node"
NODE = Path(
    os.environ.get("JEV_TEST_NODE")
    or (
        str(ISOLATED_NODE)
        if ISOLATED_NODE.exists()
        else shutil.which("node") or "/missing-node"
    )
)


class InstallerTests(RuntimeCase):
    def install(self):
        return install(self.home, NODE, self.root, "source")

    def test_idempotent_preserves_provider_auth_effort_and_uninstall(self):
        # Deliberately synthetic. Tests never read a real auth file.
        secret = "SYNTHETIC-ONLY-AUTH-CANARY"
        native = (
            'model = "owner-model"\nmodel_reasoning_effort = "max"\nmodel_provider = "owner"\n'
            'cli_auth_credentials_store = "keyring"\n'
            '[model_providers.owner]\nname = "Owner"\nbase_url = "https://invalid.example"\n'
            f'http_headers = {{ Authorization = "{secret}" }}\n'
        )
        auth = self.native("auth.json", json.dumps({"api_key": secret}))
        self.native("config.toml", native)
        self.native("AGENTS.md", "Owner guidance without trailing newline")
        hooks = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "owner-hook"}],
                    }
                ]
            }
        }
        self.native("hooks.json", json.dumps(hooks))
        result = self.install()
        self.assertTrue(result["installed"])
        first = {
            name: (self.home.codex / name).read_bytes()
            for name in ("config.toml", "AGENTS.md", "hooks.json")
        }
        self.install()
        for name, value in first.items():
            self.assertEqual((self.home.codex / name).read_bytes(), value)
        config = tomllib.loads(first["config.toml"].decode())
        self.assertEqual(config["model_reasoning_effort"], "max")
        self.assertEqual(config["model_provider"], "owner")
        env = config["mcp_servers"]["jev_context"]["env"]
        self.assertEqual(env["JEV_PYTHON"], str(Path(sys.executable).resolve()))
        self.assertNotIn("PATH", env)
        for file in self.home.path.rglob("*"):
            if file.is_file():
                self.assertNotIn(secret.encode(), file.read_bytes())
        self.assertIn(str(MANAGE), first["AGENTS.md"].decode())
        self.assertIn("--codex-home", first["AGENTS.md"].decode())
        self.assertTrue(uninstall(self.home)["uninstalled"])
        self.assertEqual((self.home.codex / "config.toml").read_text(), native)
        self.assertEqual(
            (self.home.codex / "AGENTS.md").read_text(),
            "Owner guidance without trailing newline",
        )
        self.assertEqual(read_json(self.home.codex / "hooks.json"), hooks)
        self.assertEqual(auth.read_text(), json.dumps({"api_key": secret}))
        self.assertTrue(uninstall(self.home)["uninstalled"])
        self.assertTrue(self.install()["installed"])

    def test_no_auth_file_or_existing_key_is_read(self):
        # Poison reads to prove installer never opens these existing secrets.
        auth = self.native("auth.json", "synthetic")
        secrets = self.home.path / "secrets"
        secrets.mkdir()
        key = secrets / "typesafe_api_key"
        key.write_text("synthetic")
        from common import read_bytes

        def guarded(path, *args, **kwargs):
            if Path(path) in {auth, key}:
                raise AssertionError("credential read")
            return read_bytes(path, *args, **kwargs)

        with (
            patch("installer.read_bytes", side_effect=guarded),
            patch("common.read_bytes", side_effect=guarded),
        ):
            self.install()
            uninstall(self.home)

    def test_release_path_upgrade_rollback_and_interrupted_recovery(self):
        self.native("config.toml", 'model_reasoning_effort="high"\n')
        self.install()
        before = {name: (self.home.codex / name).read_bytes()
                  for name in ("config.toml", "hooks.json", "AGENTS.md")}
        upgrade = self.base / "new-release"
        (upgrade / "src").mkdir(parents=True)
        (upgrade / "src/mcp-server.mjs").write_text("// synthetic installer fixture\n")
        actual_write = atomic_write

        def failing(path, data):
            if path == self.home.codex / "hooks.json" and b"new-release" in data:
                raise OSError("simulated interrupted upgrade")
            return actual_write(path, data)

        with patch("installer.CHECKOUT", upgrade), patch("installer.MANAGE", upgrade / "runtime/manage.py"):
            with patch("common.atomic_write", side_effect=failing):
                with self.assertRaises(OSError):
                    self.install()
            self.assertEqual(self.read_state("installation.json")["status"], "pending")
            for name, content in before.items():
                self.assertEqual((self.home.codex / name).read_bytes(), content)
            self.assertTrue(self.install()["installed"])
            self.assertIn("new-release", (self.home.codex / "config.toml").read_text())
            self.assertIn("new-release", (self.home.codex / "hooks.json").read_text())
        self.assertTrue(self.install()["installed"])
        for name, content in before.items():
            self.assertEqual((self.home.codex / name).read_bytes(), content)
        self.assertTrue(uninstall(self.home)["uninstalled"])

    def test_caught_write_failure_rolls_back_and_retry_is_idempotent(self):
        config = self.native("config.toml", 'model_reasoning_effort = "max"\n')
        agents = self.native("AGENTS.md", "Owner\n")

        def failing(path, data):
            if path == agents:
                raise OSError("synthetic write failure")
            atomic_write(path, data)

        with (
            patch("common.atomic_write", side_effect=failing),
            self.assertRaises(OSError),
        ):
            self.install()
        self.assertEqual(config.read_text(), 'model_reasoning_effort = "max"\n')
        self.assertEqual(agents.read_text(), "Owner\n")
        self.assertFalse((self.home.codex / "hooks.json").exists())
        self.assertEqual(self.read_state("installation.json")["status"], "pending")
        self.assertTrue(self.install()["installed"])
        hooks = read_json(self.home.codex / "hooks.json")
        self.assertTrue(all(len(hooks["hooks"][event]) == 1 for event in EVENTS))

    def test_pending_install_can_be_uninstalled_after_failure(self):
        def failing(path, data):
            if path == self.home.codex / "config.toml":
                raise OSError("synthetic")
            atomic_write(path, data)

        with (
            patch("common.atomic_write", side_effect=failing),
            self.assertRaises(OSError),
        ):
            self.install()
        self.assertTrue(uninstall(self.home)["uninstalled"])

    def test_owner_edits_survive_uninstall_and_reinstall_fails(self):
        self.install()
        file = self.home.codex / "config.toml"
        file.write_text(
            file.read_text().replace('startup_timeout_sec = 20', 'startup_timeout_sec = 25')
        )
        with self.assertRaises(ValueError):
            self.install()
        result = uninstall(self.home)
        self.assertIn("config.toml:mcp", result["conflicts"])
        self.assertIn('startup_timeout_sec = 25', file.read_text())
        with self.assertRaises(ValueError):
            self.install()

    def test_existing_mcp_conflict_no_changes(self):
        file = self.native(
            "config.toml", '[mcp_servers.jev_context]\ncommand = "owner"\n'
        )
        before = file.read_bytes()
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(file.read_bytes(), before)
        self.assertFalse((self.home.path / "installation.json").exists())

    def test_missing_model_and_explicit_guidance_remain_owner_choices(self):
        self.native("config.toml", 'model_reasoning_effort="high"\n')
        self.native("AGENTS.md", "Keep the owner's selected model.\n")
        self.install()
        config = tomllib.loads((self.home.codex / "config.toml").read_text())
        self.assertNotIn("model", config)
        self.assertEqual(config["model_reasoning_effort"], "high")
        self.assertNotIn("Use Astra only", (self.home.codex / "AGENTS.md").read_text())
        self.assertTrue(uninstall(self.home)["uninstalled"])
        self.assertEqual((self.home.codex / "config.toml").read_text(), 'model_reasoning_effort="high"\n')

    def test_matching_unowned_hook_is_not_adopted_or_removed(self):
        group = {"hooks": [{"type": "command", "command": shlex.join([
            str(Path(sys.executable).resolve()), str(MANAGE), "hook", "--codex-home", str(self.home.codex)
        ]), "timeout": 30, "additionalContextLimit": 400}]}
        hooks = self.native("hooks.json", json.dumps({"hooks": {"SessionStart": [group]}}))
        before = hooks.read_bytes()
        with self.assertRaisesRegex(ValueError, "unowned hook"):
            self.install()
        self.assertEqual(hooks.read_bytes(), before)
        self.assertFalse((self.home.path / "installation.json").exists())
        self.assertTrue(uninstall(self.home)["uninstalled"])
        self.assertEqual(hooks.read_bytes(), before)

    def test_missing_or_bad_entrypoint_and_node_fail_before_mutation(self):
        with self.assertRaises(ValueError):
            install(self.home, "/missing/node", self.root, "source")
        with self.assertRaises(ValueError):
            install(self.home, NODE, self.root, "typo")
        with (
            patch("installer.CHECKOUT", self.base / "missing"),
            self.assertRaises(ValueError),
        ):
            install(self.home, NODE, self.root, "dist")
        self.assertFalse((self.home.codex / "config.toml").exists())

    def test_installer_backup_retention_is_bounded(self):
        for number in range(11):
            self.install()
            config = self.home.codex / "config.toml"
            config.write_text(config.read_text() + f"\n# owner edit {number}\n")
        self.assertLessEqual(
            len(list((self.home.path / "install-backups").iterdir())), 8
        )

    def test_total_budget_defaults_disabled_validates_and_preserves_owner_cap(self):
        self.install()
        value = self.read_state("config.json")
        self.assertEqual(value["total_budget_usd"], 0)
        self.assertFalse(value["enabled"])
        self.assertFalse(value["live_validated"])
        for cap in (True, -1, float("inf"), float("nan"), "10"):
            with self.assertRaises(ValueError):
                validate_config(
                    {
                        **DEFAULTS,
                        "allowed_roots": [str(self.root)],
                        "total_budget_usd": cap,
                    }
                )
        value.update(
            total_budget_usd=10, validation_budget_usd=10, monthly_budget_usd=10
        )
        self.state("config.json", value)
        self.install()
        current = self.read_state("config.json")
        self.assertEqual(current["total_budget_usd"], 10)
        self.assertFalse(current["enabled"])
