import json
import os
from pathlib import Path

from common import read_json
from releases import create_manifest, materialize, verify
from test_support import RuntimeCase


class ReleaseTests(RuntimeCase):
    def source(self):
        root = self.base / "source"
        for name, body in {
            "package.json": '{"name":"offline","version":"1","engines":{"node":">=22.13"}}',
            "package-lock.json": '{"lockfileVersion":3,"packages":{}}',
            "LICENSE": "MIT fixture", "NOTICE.md": "Attribution fixture",
            "THIRD_PARTY_NOTICES.txt": "Dependency fixture",
            "runtime/manage.py": "# fixture\n", "runtime/invocations.sql": "-- fixture\n",
            "src/hardened-policy.mjs": "export const POLICY='fixture';\n",
            "scripts/investigate.mjs": "// fixture\n",
            "dist/server.mjs": "// bundled fixture\n", "dist/live-smoke.mjs": "// fixture\n",
        }.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        create_manifest(root)
        return root

    def test_content_addressed_copy_is_stable_and_checkout_edits_do_not_modify_it(self):
        root = self.source()
        first = materialize(self.home, root)
        second = materialize(self.home, root)
        self.assertEqual(first, second)
        self.assertEqual(Path(first["root"]).name, first["id"])
        self.assertEqual(verify(Path(first["root"]))["id"], first["id"])
        self.assertEqual((Path(first["root"]) / "runtime/manage.py").stat().st_mode & 0o777, 0o400)
        (root / "runtime/manage.py").write_text("# changed checkout\n")
        with self.assertRaises(ValueError):
            materialize(self.home, root)
        self.assertEqual((Path(first["root"]) / "runtime/manage.py").read_text(), "# fixture\n")
        create_manifest(root)
        self.assertNotEqual(materialize(self.home, root)["id"], first["id"])

    def test_corrupt_or_linked_artifact_and_unsafe_manifest_never_install(self):
        root = self.source()
        file = root / "dist/server.mjs"
        before = file.read_bytes()
        file.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            materialize(self.home, root)
        file.unlink()
        outside = self.base / "outside"
        outside.write_bytes(before)
        file.symlink_to(outside)
        with self.assertRaises(ValueError):
            materialize(self.home, root)
        file.unlink()
        os.link(outside, file)
        with self.assertRaises(ValueError):
            materialize(self.home, root)
        file.unlink()
        file.write_bytes(before)
        manifest = read_json(root / "release-manifest.json")
        manifest["files"]["../outside"] = next(iter(manifest["files"].values()))
        (root / "release-manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            materialize(self.home, root)
        self.assertFalse((self.home.path / "installation.json").exists())

    def test_existing_corrupt_release_is_preserved_not_overwritten(self):
        root = self.source()
        installed = materialize(self.home, root)
        file = Path(installed["root"]) / "dist/server.mjs"
        file.chmod(0o600)
        file.write_text("corrupt evidence")
        with self.assertRaises(ValueError):
            materialize(self.home, root)
        self.assertEqual(file.read_text(), "corrupt evidence")

    def test_manifest_ignores_credentials_and_includes_locked_dependencies(self):
        root = self.source()
        (root / ".env").write_text("SYNTHETIC_ONLY")
        (root / "runtime/test_private.py").write_text("SYNTHETIC_ONLY")
        create_manifest(root)
        manifest = read_json(root / "release-manifest.json")
        self.assertNotIn(".env", manifest["files"])
        self.assertNotIn("runtime/test_private.py", manifest["files"])
        self.assertIn("dist/dependency-lock.json", manifest["files"])

    def test_release_limit_preserves_existing_history(self):
        root = self.source()
        folder = self.home.path / "releases"
        folder.mkdir()
        for index in range(8):
            (folder / f"retained-{index}").mkdir()
        with self.assertRaisesRegex(ValueError, "retention limit"):
            materialize(self.home, root)
        self.assertEqual(len(list(folder.iterdir())), 8)
