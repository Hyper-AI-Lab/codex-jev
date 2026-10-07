import shutil
from pathlib import Path
from unittest.mock import patch

from common import atomic_write, encoded, write_transaction
from installer import install, uninstall
from releases import create_manifest
from skill_files import FILES, PREFIX
from test_installer import NODE
from test_support import RuntimeCase


class SkillFilesTests(RuntimeCase):
    def test_install_uninstall_preserves_unrelated_skill_and_accounting(self):
        (self.home.codex / "skills/owner").mkdir(parents=True)
        other = self.native("skills/owner/SKILL.md", "Owner material")
        self.state("budget-sentinel.json", {"count": 7})
        result = install(self.home, NODE, self.root)
        for name in FILES:
            self.assertEqual((self.home.codex / PREFIX / name).read_bytes(),
                             (Path(result["release_root"]) / PREFIX / name).read_bytes())
        install(self.home, NODE, self.root)
        self.assertTrue(uninstall(self.home)["uninstalled"])
        self.assertTrue(all(not (self.home.codex / PREFIX / name).exists() for name in FILES))
        self.assertEqual(other.read_text(), "Owner material")
        self.assertEqual(self.read_state("budget-sentinel.json"), {"count": 7})

    def test_unowned_skill_is_never_adopted_even_if_identical(self):
        source = Path(__file__).resolve().parents[1] / PREFIX / "SKILL.md"
        (self.home.codex / PREFIX).mkdir(parents=True)
        target = self.native(PREFIX + "SKILL.md", source.read_text())
        with self.assertRaisesRegex(ValueError, "Unowned"):
            install(self.home, NODE, self.root)
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertFalse((self.home.codex / "config.toml").exists())

    def test_owner_edited_skill_survives_install_and_uninstall(self):
        install(self.home, NODE, self.root)
        target = self.home.codex / PREFIX / "SKILL.md"
        target.write_text("Owner instruction")
        with self.assertRaisesRegex(ValueError, "owner-edited"):
            install(self.home, NODE, self.root)
        self.assertIn("skill:SKILL.md", uninstall(self.home)["conflicts"])
        self.assertEqual(target.read_text(), "Owner instruction")

    def test_caught_failure_rolls_back_skill_and_recovers_pending_intent(self):
        target = self.home.codex / PREFIX / "SKILL.md"
        manifest = self.home.path / "installation.json"
        def failing(path, data):
            if path == manifest and b'"status": "installed"' in data:
                raise OSError("synthetic disk failure")
            atomic_write(path, data)
        with patch("common.atomic_write", side_effect=failing), self.assertRaises(OSError):
            install(self.home, NODE, self.root)
        self.assertFalse(target.exists())
        self.assertEqual(self.read_state("installation.json")["status"], "pending")
        install(self.home, NODE, self.root)
        self.assertTrue(target.exists())

    def test_rollback_to_no_skill_release_removes_only_owned_skill(self):
        current = install(self.home, NODE, self.root)
        old = self.base / "old-release"
        shutil.copytree(current["release_root"], old)
        for path in (old, *old.rglob("*")):
            path.chmod(0o700 if path.is_dir() else 0o600)
        shutil.rmtree(old / "skills")
        create_manifest(old)
        with patch("installer.CHECKOUT", old):
            install(self.home, NODE, self.root)
        self.assertFalse((self.home.codex / PREFIX / "SKILL.md").exists())
        self.assertEqual(self.read_state("installation.json")["skill"], {})
        install(self.home, NODE, self.root)
        self.assertTrue((self.home.codex / PREFIX / "SKILL.md").exists())

    def test_partial_upgrade_can_remove_old_or_new_owned_skill_only(self):
        install(self.home, NODE, self.root)
        manifest = self.read_state("installation.json")
        old = dict(manifest["skill"])
        manifest["status"] = "pending"
        manifest["previous_owned"] = {"skill": old, "blocks": manifest["blocks"], "hooks": manifest["hooks"]}
        manifest["skill"] = {name: "0" * 64 for name in old}
        self.state("installation.json", manifest)
        self.assertTrue(uninstall(self.home)["uninstalled"])

    def test_deletion_rollback_restores_even_empty_files(self):
        empty = self.native("empty.txt", "")
        fails = self.home.codex / "fail.txt"
        def failing(path, data):
            if path == fails:
                raise OSError("synthetic")
            atomic_write(path, data)
        with patch("common.atomic_write", side_effect=failing), self.assertRaises(OSError):
            write_transaction({empty: None, fails: encoded({"value": 1})})
        self.assertTrue(empty.exists())
        self.assertEqual(empty.read_bytes(), b"")
