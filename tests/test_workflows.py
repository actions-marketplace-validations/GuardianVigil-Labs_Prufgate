"""Release safety of the GitHub workflows and the composite action.

- every `uses:` is pinned to a full commit SHA (a tag can be moved);
- nothing publishes on a branch push: images and releases come only from a
  version tag or a maintainer starting the workflow by hand.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted([*(ROOT / ".github" / "workflows").glob("*.yml"), *(ROOT / ".github" / "workflows").glob("*.yaml")])
FILES = WORKFLOWS + [ROOT / "action.yml"]
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def uses(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "uses" and isinstance(v, str):
                yield v
            else:
                yield from uses(v)
    elif isinstance(node, list):
        for v in node:
            yield from uses(v)


def triggers(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML reads the bare key `on` as the boolean True.
    on = doc.get("on", doc.get(True))
    return on if isinstance(on, dict) else {k: None for k in ([on] if isinstance(on, str) else on)}


class WorkflowSafety(unittest.TestCase):
    def test_every_action_is_pinned_to_a_commit_sha(self):
        for path in FILES:
            for ref in uses(yaml.safe_load(path.read_text(encoding="utf-8"))):
                if ref.startswith("./"):
                    continue
                self.assertRegex(ref, PINNED, f"{path.name}: {ref} is not pinned to a commit SHA")

    def test_nothing_publishes_on_a_branch_push(self):
        # Any workflow that can write packages or repository contents publishes.
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            if not re.search(r"^\s*(?:packages|contents):\s*write", text, re.M):
                continue
            on = triggers(path)
            self.assertEqual(set(on) - {"push", "workflow_dispatch"}, set(), f"{path.name}: unexpected trigger")
            if "push" in on:
                push = on["push"]
                # A bare `push:` (or `on: [push]`) runs on every branch push.
                self.assertIsInstance(push, dict, f"{path.name}: push must list tags only")
                self.assertEqual(set(push), {"tags"}, f"{path.name}: push must be tags only")

    def test_a_bare_push_trigger_is_caught(self):
        for on in ({"push": None, "workflow_dispatch": None}, {"push": None}):
            self.assertNotIsInstance(on["push"], dict)

    def test_the_pin_pattern_works(self):
        self.assertRegex("actions/checkout@" + "a" * 40, PINNED)
        self.assertNotRegex("actions/checkout@v7", PINNED)
        self.assertNotRegex("actions/checkout@main", PINNED)


class ReleaseSafety(unittest.TestCase):
    def setUp(self):
        self.release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
        self.jobs = self.release["jobs"]

    def test_only_a_version_tag_starts_a_release(self):
        on = self.release.get("on", self.release.get(True))
        self.assertEqual(on, {"push": {"tags": ["v*"]}})

    def test_the_release_runs_only_in_the_public_repository(self):
        # Every job depends on the guarded checks job.
        self.assertEqual(self.jobs["checks"]["if"], "github.repository == 'GuardianVigil-Labs/Prufgate'")
        for name, job in self.jobs.items():
            if name != "checks":
                self.assertTrue(job.get("needs"), name)

    def test_pypi_uses_trusted_publishing_behind_the_approval_environment(self):
        job = self.jobs["pypi"]
        self.assertEqual(job["environment"]["name"], "pypi")
        self.assertEqual(job["permissions"], {"id-token": "write"})
        step = next(st for st in job["steps"] if "gh-action-pypi-publish" in st.get("uses", ""))
        self.assertNotIn("password", step.get("with", {}))

    def test_attest_sbom_path_is_a_literal_file(self):
        # actions/attest reads sbom-path as one file; a glob fails after PyPI has published.
        for job in self.jobs.values():
            for step in job.get("steps", []):
                path = step.get("with", {}).get("sbom-path")
                if path:
                    self.assertNotRegex(path, r"[*?\[]")

    def test_jobs_get_least_privilege(self):
        self.assertEqual(self.release["permissions"], {})
        for name in ("checks", "build", "vscode", "marketplace"):
            self.assertEqual(self.jobs[name]["permissions"], {"contents": "read"}, name)

    def test_the_marketplace_publishes_the_checked_vsix_behind_its_environment(self):
        build, publish = self.jobs["vscode"], self.jobs["marketplace"]
        self.assertEqual(build["needs"], "checks")
        # Publishing waits for the release job, which attests the same .vsix first.
        self.assertEqual(publish["needs"], ["vscode", "release"])
        self.assertEqual(publish["environment"]["name"], "vscode-marketplace")
        runs = "\n".join(st.get("run", "") for st in build["steps"])
        self.assertIn('= "${TAG}"', runs)  # the version must equal the tag
        self.assertIn("vsce package --no-dependencies", runs)
        step = next(st for st in publish["steps"] if "vsce publish" in st.get("run", ""))
        self.assertIn("--packagePath", step["run"])
        self.assertIn('if [ -z "${VSCE_PAT}" ]', step["run"])  # a missing token fails, never skips
        self.assertEqual(step["env"]["VSCE_PAT"], "${{ secrets.VSCE_PAT }}")
        # The token is in no other job, and every checkout drops its credentials.
        for name, job in self.jobs.items():
            if name != "marketplace":
                self.assertNotIn("VSCE_PAT", yaml.safe_dump(job), name)
            for st in job["steps"]:
                if "actions/checkout" in st.get("uses", ""):
                    self.assertIs(st["with"]["persist-credentials"], False, name)
        self.assertIn("vscode", self.jobs["release"]["needs"])


class VersionsAgree(unittest.TestCase):
    def test_image_label_and_action_default_match_the_package_version(self):
        version = re.search(r'__version__ = "([^"]+)"', (ROOT / "prufgate/__init__.py").read_text()).group(1)
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(f'org.opencontainers.image.version="{version}"', dockerfile)
        action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        self.assertEqual(action["inputs"]["image"]["default"], f"ghcr.io/guardianvigil-labs/prufgate:{version}")
        self.assertIn(f"## [{version}]", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
        server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        self.assertEqual({server["version"], server["packages"][0]["version"]}, {version})
        # The MCP Registry verifies the PyPI package by this line in its README.
        self.assertIn(f"<!-- mcp-name: {server['name']} -->", (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_locked_requirements_cover_every_runtime_dependency(self):
        # docs/UPGRADING.md installs a checkout with `--require-hashes -r requirements.txt` then `--no-deps .`.
        deps = re.findall(r'^\s*"([A-Za-z0-9_.-]+)[^"]*"', (ROOT / "pyproject.toml").read_text().split("dependencies = [", 1)[1].split("]", 1)[0], re.M)
        locked = {m.lower() for m in re.findall(r"^([A-Za-z0-9_.-]+)==", (ROOT / "requirements.txt").read_text(), re.M)}
        self.assertEqual({d.lower() for d in deps} - locked, set())

    def test_ci_guide_lists_every_action_input_with_its_default(self):
        action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))["inputs"]
        guide = (ROOT / "docs/CI_INTEGRATION.md").read_text(encoding="utf-8")
        table = guide.split("| Input | Default | Meaning |", 1)[1].split("\n\n", 1)[0]
        rows = dict(re.findall(r"^\| `(\w+)` \| ([^|]+) \|", table, re.M))
        self.assertEqual(set(rows), set(action))
        for name, spec in action.items():
            literal = re.fullmatch(r"`([^`]*)`", rows[name].strip())
            if literal and "${{" not in spec["default"]:
                self.assertEqual(literal.group(1), spec["default"], name)


if __name__ == "__main__":
    unittest.main()
