import json
import os
from unittest.mock import patch

from retrieval import classify
from test_support import RuntimeCase


class RetrievalTests(RuntimeCase):
    def setUp(self):
        super().setUp()
        self.write("large.log", "diagnostic context\n" * 5000)
        self.config = {"enabled": True, "additional_exclusions": []}

    def classification(self, command, **kwargs):
        return classify({"tool_name": "exec_command", "cwd": str(self.root),
                         "tool_input": {"cmd": command, **kwargs}}, self.root, self.config)

    def test_broad_search_and_large_read_redirect(self):
        for command in ('rg -n "broad discovery" .', 'grep -rn "broad discovery" .',
                        'rg -e failure -e timeout .', 'rg -g "*.txt" failure .'):
            with self.subTest(command=command):
                self.assertEqual(self.classification(command)["tool"], "search_workspace_evidence")
        for command in ('cat large.log', 'head -n 400 large.log', 'tail -n400 large.log',
                        "sed -n '1,400p' large.log"):
            self.assertEqual(self.classification(command)["tool"], "read_large_text_evidence")

    def test_identifiers_metadata_and_bounded_reads_stay_native(self):
        for command in ('rg -n source_hash .', 'rg CompanyContextSync .', 'rg pkg.handler .',
                        'rg --files', 'rg -l pattern .', 'rg --count pattern .',
                        'cat source.txt', "sed -n '1,80p' large.log", 'tail -n80 large.log',
                        'head large.log'):
            with self.subTest(command=command):
                self.assertEqual(self.classification(command)["state"], "native")

    def test_complex_shell_and_unknown_commands_never_rewrite(self):
        for command in ('rg pattern . | head', 'cat large.log > output', 'rg x . && rm x',
                        'cat $(pwd)/large.log', 'cat `pwd`/large.log', 'cat large.log\ntrue',
                        'rg --pre something pattern .', 'rg -uuu pattern .', 'rg "broken',
                        'sed -i s/a/b/ source.txt', 'npm test', 'git diff', 'jq . data.json',
                        'env rg pattern .', 'python runtime/manage.py resume', 'rg pattern . # override',
                        'x' * 20000):
            with self.subTest(command=command):
                value = self.classification(command)
                self.assertEqual(value["state"], "unclassified")
                self.assertNotIn("updatedInput", value)

    def test_private_ignored_symlink_and_external_paths_never_redirect(self):
        self.write(".gitignore", "ignored/\n")
        self.write("ignored/large.log", "x" * 60000)
        self.write(".env", "x" * 60000)
        self.write("api-token.txt", "x" * 60000)
        (self.root / "alias").symlink_to(self.root / "large.log")
        os.link(self.root / "large.log", self.root / "hardlink")
        for path in (".env", "api-token.txt", "ignored/large.log", "alias", "hardlink", "../outside", "/etc/passwd"):
            self.assertEqual(self.classification(f'cat {path}')["state"], "native_exception")
        self.assertEqual(self.classification('rg pattern .', workdir=str(self.root.parent))["state"], "native_exception")

    def test_disabled_or_excluded_retrieval_records_native_exception(self):
        self.config["enabled"] = False
        self.assertEqual(self.classification('rg pattern .')["reason"], "retrieval_disabled")
        self.config["enabled"] = True
        self.config["retrieval_default"] = False
        self.assertEqual(self.classification('cat large.log')["reason"], "retrieval_disabled")
        self.config["retrieval_default"] = True
        self.config["additional_exclusions"] = ["large.*"]
        self.assertEqual(self.classification('cat large.log')["reason"], "ineligible_paths")

    def test_subdirectory_and_quoted_paths_supported_without_source_read(self):
        self.write("nested/my log.txt", "x" * 60000)
        with patch("pathlib.Path.read_bytes", side_effect=AssertionError("no content scan")):
            self.assertEqual(self.classification('cat "my log.txt"', workdir=str(self.root / "nested"))["state"], "redirect")

    def test_result_contains_only_codes_not_source_query_or_command(self):
        result = self.classification('rg "PRIVATE-SYNTHETIC-CANARY" .')
        self.assertNotIn("PRIVATE-SYNTHETIC", json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertEqual(classify({"tool_name": "apply_patch"}, self.root, self.config)["state"], "not_covered")

    def test_environment_override_cannot_change_ignore_source(self):
        self.write(".gitignore", "ignored.log\n")
        self.write("ignored.log", "x" * 60000)
        with patch.dict(os.environ, {"GIT_WORK_TREE": str(self.root.parent), "GIT_DIR": "/missing"}):
            self.assertEqual(self.classification('cat ignored.log')["state"], "native_exception")

    def test_shell_expansion_or_huge_numeric_range_is_unclassified(self):
        for cmd in ("tail -n" + "9" * 5000 + " large.log", 'cat ~/*.log', 'rg "$(evil)" .'):
            self.assertIn(self.classification(cmd)["state"], {"unclassified", "native_exception"})
