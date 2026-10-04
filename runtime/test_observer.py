import os
import plistlib
import subprocess
import sys
import tomllib
from pathlib import Path
from unittest.mock import patch

from common import atomic_write, locked
from installer import MANAGE
from observer import (
    install_observer,
    observer_status,
    service_definition,
    uninstall_observer,
)
from test_support import RuntimeCase


class ObserverTests(RuntimeCase):
    def install(self, platform="linux"):
        return install_observer(self.home, 43181, platform, self.base / "service home")

    def test_linux_idempotent_optional_install_uninstall_no_daemon(self):
        native = 'model = "owner"\nmodel_reasoning_effort = "max"\n'
        self.native("config.toml", native)
        # Only Git checks may execute; install must never call a service manager.
        with patch("observer.os.getuid", return_value=1000):
            result = self.install()
        self.assertFalse(result["started"])
        self.assertFalse(result["enabled"])
        service = Path(result["service_path"])
        text = service.read_text()
        self.assertIn("[Service]", text)
        self.assertIn("StandardOutput=null", text)
        self.assertIn("StandardError=null", text)
        self.assertIn(str(self.home.path / "releases"), text)
        self.assertIn("/runtime/manage.py", text)
        first = (self.home.codex / "config.toml").read_bytes()
        self.install()
        self.assertEqual((self.home.codex / "config.toml").read_bytes(), first)
        otel = tomllib.loads(first.decode())["otel"]
        self.assertFalse(otel["log_user_prompt"])
        self.assertEqual(
            otel["exporter"]["otlp-http"],
            {"endpoint": "http://127.0.0.1:43181/v1/logs", "protocol": "json"},
        )
        self.assertFalse(observer_status(self.home)["running_lock_observed"])
        self.assertTrue(uninstall_observer(self.home)["uninstalled"])
        self.assertFalse(service.exists())
        self.assertEqual((self.home.codex / "config.toml").read_text(), native)
        self.assertTrue(uninstall_observer(self.home)["uninstalled"])
        self.assertTrue(self.install()["installed"])

    def test_mac_plist_is_portable_and_suppresses_logs(self):
        result = self.install("darwin")
        value = plistlib.loads(Path(result["service_path"]).read_bytes())
        self.assertEqual(
            value["ProgramArguments"][0], str(Path(sys.executable).resolve())
        )
        self.assertIn(str(self.home.codex), value["ProgramArguments"])
        self.assertEqual(value["StandardOutPath"], "/dev/null")
        self.assertEqual(value["StandardErrorPath"], "/dev/null")
        self.assertEqual(value["Umask"], 0o077)
        self.assertFalse(result["started"])
        self.assertTrue(uninstall_observer(self.home)["uninstalled"])

    def test_existing_otel_or_profile_and_env_are_preserved(self):
        for native in (
            '[otel]\nexporter = "none"\n',
            '[profiles.work.otel]\nexporter = "none"\n',
        ):
            file = self.native("config.toml", native)
            result = self.install()
            self.assertFalse(result["installed"])
            self.assertTrue(result["conflicts"])
            self.assertEqual(file.read_text(), native)
            self.assertFalse((self.home.path / "observer-installation.json").exists())
        self.native("config.toml", "")
        with patch.dict(
            os.environ, {"OTEL_EXPORTER_OTLP_HEADERS": "SYNTHETIC-PRIVATE-HEADER"}
        ):
            result = self.install()
            self.assertFalse(result["installed"])
            self.assertNotIn("SYNTHETIC-PRIVATE-HEADER", str(result))

    def test_semantically_identical_owned_otel_formatting_is_preserved_on_upgrade(self):
        self.install()
        file = self.home.codex / "config.toml"
        formatted = file.read_text().replace("log_user_prompt = false", "log_user_prompt=false # owner formatting")
        file.write_text(formatted)
        self.assertTrue(self.install()["installed"])
        self.assertEqual(file.read_text(), formatted)
        self.assertTrue(uninstall_observer(self.home)["uninstalled"])

    def test_native_trust_table_inserted_inside_markers_is_never_owned_or_removed(self):
        self.install()
        file = self.home.codex / "config.toml"
        trust = '[hooks.state]\nfixture = "native-owner-controlled"\n'
        file.write_text(file.read_text().replace("# END jev-context:observer-otel", trust + "# END jev-context:observer-otel"))
        before = tomllib.loads(file.read_text())
        self.assertTrue(self.install()["installed"])
        self.assertEqual(tomllib.loads(file.read_text()), before)
        owned = self.read_state("observer-installation.json")["otel"]["text"]
        self.assertNotIn("hooks.state", owned)
        self.assertTrue(uninstall_observer(self.home)["uninstalled"])
        self.assertEqual(tomllib.loads(file.read_text())["hooks"], before["hooks"])

    def test_edited_service_or_otel_preserved(self):
        result = self.install()
        service = Path(result["service_path"])
        before = service.read_bytes()
        service.write_bytes(before + b"# owner edit\n")
        self.assertFalse(uninstall_observer(self.home)["uninstalled"])
        self.assertIn(b"# owner edit", service.read_bytes())
        service.write_bytes(before)
        config = self.home.codex / "config.toml"
        config.write_text(config.read_text().replace("43181", "43182"))
        self.assertFalse(self.install()["installed"])
        self.assertFalse(uninstall_observer(self.home)["uninstalled"])
        self.assertIn("43182", config.read_text())

    def test_running_lock_prevents_install_and_removal(self):
        self.install()
        with locked(self.home.path / "observer.lock"):
            self.assertTrue(observer_status(self.home)["running_lock_observed"])
            with self.assertRaises(TimeoutError):
                self.install()
            with self.assertRaises(TimeoutError):
                uninstall_observer(self.home)

    def test_write_failure_rolls_back_config_and_can_retry(self):
        config = self.native("config.toml", 'model_reasoning_effort = "max"\n')

        def failing(path, data):
            if path.suffix == ".service":
                raise OSError("synthetic")
            atomic_write(path, data)

        with (
            patch("common.atomic_write", side_effect=failing),
            self.assertRaises(OSError),
        ):
            self.install()
        self.assertEqual(config.read_text(), 'model_reasoning_effort = "max"\n')
        self.assertTrue(self.install()["installed"])

    def test_owned_service_upgrade_retries_after_interruption_without_adopting_owner_edits(self):
        first = self.install()
        path = Path(first["service_path"])
        old = path.read_bytes()
        actual_definition = service_definition
        def upgraded(*args, **kwargs):
            target, content, start, stop = actual_definition(*args, **kwargs)
            return target, content + b"# upgraded fixture\n", start, stop
        def failing(target, data):
            if target == path:
                raise OSError("interrupted service update")
            atomic_write(target, data)
        with patch("observer.service_definition", side_effect=upgraded):
            with patch("common.atomic_write", side_effect=failing), self.assertRaises(OSError):
                self.install()
            self.assertEqual(path.read_bytes(), old)
            self.assertTrue(self.install()["installed"])
            self.assertTrue(path.read_bytes().endswith(b"# upgraded fixture\n"))

    def test_conflicting_unowned_service_is_not_overwritten(self):
        path, _, _, _ = service_definition(
            self.home, 43181, "linux", self.base / "service home"
        )
        path.parent.mkdir(parents=True)
        path.write_text("owner service")
        result = self.install()
        self.assertFalse(result["installed"])
        self.assertEqual(path.read_text(), "owner service")
        self.assertFalse((self.home.codex / "config.toml").exists())

    def test_observer_cli_installs_and_removes_definitions_only(self):
        def command(action, *args):
            return subprocess.run(
                [
                    sys.executable,
                    str(MANAGE),
                    action,
                    "--codex-home",
                    str(self.home.codex),
                    *args,
                ],
                capture_output=True,
                timeout=10,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )

        result = command(
            "observer-install",
            "--platform",
            "linux",
            "--service-root",
            str(self.base / "cli services"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(command("observer-status").returncode, 0)
        self.assertEqual(command("observer-uninstall").returncode, 0)
