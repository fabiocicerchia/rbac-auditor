"""Tests that docs/ says what rbac_audit.py does.

stdlib unittest, run with `python3 -m unittest discover tests`.

The rule table, the exit-code table and the policy examples are what a reader
copies into CI. A doc that drifts from the code is a gate configured wrong.
"""

import argparse
import re
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import rbac_audit as ra

DOCS = ROOT / "docs"
RULE_ROW = re.compile(r"^\| `([a-z-]+)`\s*\|.*\|\s*(\w+)\s*\|$", re.MULTILINE)
EXIT_ROW = re.compile(r"^\| (\d+)\s*\|", re.MULTILINE)
YAML_BLOCK = re.compile(r"^```yaml\n(.*?)^```", re.MULTILINE | re.DOTALL)


def read(name):
    return (DOCS / name).read_text()


class RuleTableTest(unittest.TestCase):
    def test_each_page_lists_every_rule_with_its_default(self):
        expected = {
            name: rule["fail"] for name, rule in ra.DEFAULT_POLICY["rules"].items()
        }
        for page in ("getting-started.md", "architecture.md"):
            with self.subTest(page=page):
                rows = RULE_ROW.findall(read(page))
                documented = {name: default != "warns" for name, default in rows}
                self.assertEqual(documented, expected)


class ExitCodeTableTest(unittest.TestCase):
    def test_table_matches_the_exit_constants(self):
        documented = {int(code) for code in EXIT_ROW.findall(read("architecture.md"))}
        defined = {
            value for name, value in vars(ra).items() if name.startswith("EXIT_")
        }
        self.assertEqual(documented, defined)


class PolicyExampleTest(unittest.TestCase):
    def test_every_policy_example_is_accepted(self):
        examples = [
            yaml.safe_load(block)
            for block in YAML_BLOCK.findall(read("getting-started.md"))
            if block.startswith("version: 1")
        ]
        self.assertGreaterEqual(len(examples), 4)
        for example in examples:
            with self.subTest(example=example):
                policy = ra.merge_policy(example)
                for name, settings in example.get("rules", {}).items():
                    for key, value in settings.items():
                        self.assertEqual(policy["rules"][name][key], value)
                self.assertEqual(policy["exempt"], example.get("exempt", []))


class CliCoverageTest(unittest.TestCase):
    def test_every_subcommand_and_flag_is_documented(self):
        page = read("getting-started.md")
        subparsers = next(
            action
            for action in ra.build_parser()._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        for command, parser in subparsers.choices.items():
            with self.subTest(command=command):
                self.assertIn(f"rbac-audit {command}", page)
            for action in parser._actions:
                if not action.option_strings or "--help" in action.option_strings:
                    continue
                with self.subTest(command=command, flag=action.option_strings):
                    self.assertTrue(
                        any(flag in page for flag in action.option_strings),
                        f"{command} {action.option_strings} is not in the docs",
                    )


if __name__ == "__main__":
    unittest.main()
