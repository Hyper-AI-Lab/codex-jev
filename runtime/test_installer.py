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
from releases import create_manifest, materialize

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
        return install(self.home, NODE, self.root)

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
        managed = self.read_state("installation.json")
        self.assertIn(str(Path(managed["release_root"]) / "runtime/manage.py"), first["AGENTS.md"].decode())
        self.assertNotIn("Do not switch models/providers or delegate", first["AGENTS.md"].decode())
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
        prior = self.read_state("installation.json")
        upgrade = self.base / "new-release"
        shutil.copytree(prior["release_root"], upgrade)
        for path in (upgrade, *upgrade.rglob("*")):
            path.chmod(0o700 if path.is_dir() else 0o600)
        manage = upgrade / "runtime/manage.py"
        manage.write_text(manage.read_text() + "\n# synthetic upgrade marker\n")
        new_id = create_manifest(upgrade)["id"]
        actual_write = atomic_write

        def failing(path, data):
            if path == self.home.codex / "hooks.json" and new_id.encode() in data:
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
            self.assertIn(new_id, (self.home.codex / "config.toml").read_text())
            self.assertIn(new_id, (self.home.codex / "hooks.json").read_text())
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

    def test_native_hook_state_is_not_misreported_as_duplicate_definitions(self):
        native = '[hooks.state]\nfixture_trust="owner-controlled"\n'
        file = self.native("config.toml", native)
        result = self.install()
        self.assertFalse(any("Inline hooks" in message for message in result["warnings"]))
        self.assertEqual(tomllib.loads(file.read_text())["hooks"]["state"]["fixture_trust"], "owner-controlled")

    def test_doctor_reports_owned_edits_without_mutating_or_manufacturing_trust(self):
        from doctor import inspect

        self.install()
        report = inspect(self.home)
        self.assertTrue(report["release"]["verified"])
        self.assertTrue(all(report["ownedHooksMatch"].values()))
        self.assertEqual(report["hookTrust"], "not_inspected_or_modified")
        file = self.home.codex / "AGENTS.md"
        file.write_text(file.read_text().replace("Check evidence_status", "Owner changed this block"))
        before = file.read_bytes()
        self.assertFalse(inspect(self.home)["ownedFragmentsMatch"]["guidance"])
        self.assertEqual(file.read_bytes(), before)

    def test_explicit_guidance_preservation_keeps_native_worker_policy(self):
        self.install()
        path = self.home.codex / "AGENTS.md"
        original = path.read_text()
        custom = original.replace("Do not switch", "Keep owner choices; do not switch")
        custom = custom.replace("Check evidence_status", "Owner permits native workers. Check evidence_status")
        path.write_text(custom)
        with self.assertRaises(ValueError):
            self.install()
        install(self.home, NODE, self.root, preserve_guidance_edits=True)
        self.assertEqual(path.read_text(), custom)
        self.install()
        self.assertEqual(path.read_text(), custom)

    def test_interrupted_custom_guidance_upgrade_recovers_without_duplicate_blocks(self):
        self.install()
        agents = self.home.codex / "AGENTS.md"
        custom = agents.read_text().replace("Check evidence_status", "Use owner workers. Check evidence_status")
        agents.write_text(custom)
        prior = self.read_state("installation.json")
        upgrade = self.base / "upgrade"
        shutil.copytree(prior["release_root"], upgrade)
        for path in (upgrade, *upgrade.rglob("*")):
            path.chmod(0o700 if path.is_dir() else 0o600)
        file = upgrade / "runtime/manage.py"
        file.write_text(file.read_text() + "\n# new fixture\n")
        create_manifest(upgrade)
        def failing(path, data):
            if path == agents:
                raise OSError("interrupted guidance update")
            atomic_write(path, data)
        with patch("installer.CHECKOUT", upgrade):
            with patch("common.atomic_write", side_effect=failing), self.assertRaises(OSError):
                install(self.home, NODE, self.root, preserve_guidance_edits=True)
            self.assertEqual(agents.read_text(), custom)
            result = install(self.home, NODE, self.root, preserve_guidance_edits=True)
            self.assertEqual(agents.read_text().count("BEGIN jev-context:guidance"), 1)
            self.assertIn("Use owner workers", agents.read_text())
            self.assertIn(result["release_root"], agents.read_text())

    def test_matching_unowned_hook_is_not_adopted_or_removed(self):
        managed = Path(materialize(self.home, CHECKOUT)["root"]) / "runtime/manage.py"
        group = {"hooks": [{"type": "command", "command": shlex.join([
            str(Path(sys.executable).resolve()), str(managed), "hook", "--codex-home", str(self.home.codex)
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
