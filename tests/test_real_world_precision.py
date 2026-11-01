"""False positives found by scanning well-known open-source projects, each fixed with
a case that must no longer be reported and a near miss that still must be.

The projects are not named here (AGENTS.md): every case is an invented example of the
idiom that was misread."""

from __future__ import annotations

import io
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from prufgate.anti_fabrication import detector
from prufgate.anti_reward_hacking.test_integrity import scan_test_file
from prufgate.bola.bola_engine import _starts_with_use_server, run_static_matrix_audit
from prufgate.contract_guard.dependency_guard import (
    load_declared_dependencies,
    scan_file_dependencies,
)


def zero_assertion(path: str, content: str, siblings: dict[str, str] | None = None) -> list[str]:
    """Names of the tests reported as zero-assertion-test."""
    with tempfile.TemporaryDirectory() as tmp:
        for rel, body in {path: content, **(siblings or {})}.items():
            (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
            (Path(tmp) / rel).write_text(body)
        found = scan_test_file(Path(tmp) / path, content)
    return sorted(f.message.split("'")[1] for f in found if f.rule == "zero-assertion-test")


class AssertionHelpers(unittest.TestCase):
    def test_go_helper_in_the_same_file_and_package(self):
        src = (
            "package cli\n\nimport \"testing\"\n\n"
            "func wantCount(err error, t *testing.T) {\n\tif err == nil {\n\t\tt.Fatal(\"want an error\")\n\t}\n}\n\n"
            "func TestTooMany(t *testing.T) {\n\terr := run(\"a\", \"b\")\n\twantCount(err, t)\n}\n\n"
            "func TestOther(t *testing.T) {\n\tcheckBody(t, \"x\")\n}\n\n"
            "func TestNothing(t *testing.T) {\n\trun(\"a\")\n}\n"
        )
        sibling = "package cli\n\nimport \"testing\"\n\nfunc checkBody(t *testing.T, s string) {\n\tif s == \"\" {\n\t\tt.Errorf(\"empty\")\n\t}\n}\n"
        self.assertEqual(zero_assertion("cli/args_test.go", src, {"cli/helpers_test.go": sibling}), ["TestNothing"])

    def test_python_and_javascript_helpers(self):
        py = (
            "def check_index(app):\n    assert app.get('/').status_code == 200\n\n"
            "def test_view(app):\n    app.add('/', view)\n    check_index(app)\n\n"
            "def test_smoke(app):\n    app.add('/', view)\n"
        )
        self.assertEqual(zero_assertion("tests/test_views.py", py), ["test_smoke"])
        js = (
            "function testRedirect(app, url, done) {\n  request(app).get('/').expect('Location', url, done);\n}\n"
            "it('redirects', function (done) {\n  testRedirect(makeApp(), '/x', done);\n});\n"
            "it('does nothing', function () {\n  makeApp();\n});\n"
        )
        self.assertEqual(zero_assertion("test/redirect.test.js", js), ["does nothing"])

    def test_a_helper_that_only_asserts_a_tautology_does_not_count(self):
        py = "def check(x):\n    assert True\n\ndef test_hidden(app):\n    check(app)\n"
        self.assertEqual(zero_assertion("tests/test_hidden.py", py), ["test_hidden"])


class AssertionStyles(unittest.TestCase):
    def test_spring_mockmvc_expectations(self):
        java = (
            "class OwnerTests {\n  @Test\n  void showsForm() throws Exception {\n"
            "    mockMvc.perform(get(\"/owners/1/edit\"))\n      .andExpect(status().isOk());\n  }\n"
            "  @Test\n  void onlyPerforms() throws Exception {\n    mockMvc.perform(get(\"/owners/1/edit\"));\n  }\n}\n"
        )
        self.assertEqual(zero_assertion("src/test/java/OwnerTests.java", java), ["onlyPerforms"])

    def test_mocha_done_handed_on_as_a_callback(self):
        js = (
            "it('emits', function (done) {\n  var app = make();\n  app.on('foo', done);\n  app.emit('foo');\n});\n"
            "it('only calls done', function (done) {\n  make();\n  done();\n});\n"
        )
        self.assertEqual(zero_assertion("test/app.test.js", js), ["only calls done"])

    def test_a_regex_literal_holding_slashes_does_not_cut_the_test_short(self):
        js = (
            "it('restores params', function (done) {\n"
            "  router.get(/\\/user:(\\w+)\\//, function (req, res, next) {\n    next();\n  });\n"
            "  request(app).get('/user:tj/').expect(200, done);\n});\n"
        )
        self.assertEqual(zero_assertion("test/router.test.js", js), [])

    def test_typescript_type_level_assertions(self):
        ts = (
            "test('infers', () => {\n  type T = z.infer<typeof schema>;\n  util.assertEqual<T, { a: string }>(true);\n});\n"
            "test('only parses', () => {\n  schema.parse({ a: 'x' });\n});\n"
        )
        self.assertEqual(zero_assertion("src/tests/infer.test.ts", ts), ["only parses"])

    def test_prophecy_and_ruby_fail(self):
        php = (
            "<?php\nclass AppTest extends TestCase {\n  public function testNoLocator(): void {\n"
            "    $c = $this->prophesize(Container::class);\n    $c->get(Argument::any())->shouldNotHaveBeenCalled();\n  }\n"
            "  public function testOnlyBuilds(): void {\n    $c = $this->prophesize(Container::class);\n  }\n}\n"
        )
        self.assertEqual(zero_assertion("tests/AppTest.php", php), ["testOnlyBuilds"])
        rb = (
            "describe 'cookies' do\n  it 'does not loop deleted cookies' do\n    cookies.delete :foo\n    cookies.each { fail }\n  end\n"
            "  it 'just deletes' do\n    cookies.delete :foo\n  end\nend\n"
        )
        self.assertEqual(zero_assertion("spec/cookies_spec.rb", rb), ["just deletes"])


class Fabrication(unittest.TestCase):
    def rules(self, rel: str, text: str) -> list[tuple[str, int]]:
        detector.apply_settings({})
        return sorted((f.rule, f.line) for f in detector.scan_text(rel, Path(rel).suffix, text))

    def test_docstring_usage_example_is_not_a_served_address(self):
        text = (
            'class Client:\n    def get(self, url):\n        """Send a GET request.\n\n'
            "        >>> client.get('https://example.org')\n        \"\"\"\n        return self.send(url)\n\n"
            'DEFAULT = "https://api.example.com/v1"\n'
        )
        self.assertEqual(self.rules("pkg/client.py", text), [("documentation-address", 9)])

    def test_abstract_method_stubs_are_not_unfinished_code(self):
        text = (
            "class Decoder:\n    def decode(self, data):\n        raise NotImplementedError()\n\n"
            "class GzipDecoder(Decoder):\n    def decode(self, data):\n        return gzip(data)\n\n"
            "class SessionInterface:\n    def open(self, app):\n        \"\"\"Open a session.\"\"\"\n        raise NotImplementedError\n\n"
            "class Billing:\n    def refund(self, order):\n        raise NotImplementedError\n\n"
            "def charge(card):\n    raise NotImplementedError\n"
        )
        self.assertEqual(self.rules("pkg/decoders.py", text),
                         [("unimplemented-production-stub", 16), ("unimplemented-production-stub", 19)])


class Imports(unittest.TestCase):
    def test_framework_provided_packages_and_example_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = ["fastapi", "sqlmodel"]\n')
            src = "import starlette\nfrom sqlalchemy import Column\nimport redis\n"
            for rel in ("app/main.py", "examples/demo.py", "docs/conf.py"):
                (ws / rel).parent.mkdir(parents=True, exist_ok=True)
                (ws / rel).write_text(src)
            mf = load_declared_dependencies(ws)
            found = {rel: [f.message.split("'")[1] for f in scan_file_dependencies(ws / rel, src, ws, mf)]
                     for rel in ("app/main.py", "examples/demo.py", "docs/conf.py")}
        self.assertEqual(found, {"app/main.py": ["redis"], "examples/demo.py": [], "docs/conf.py": []})


    def test_import_under_a_flag_set_by_an_optional_import(self):
        src = (
            "try:\n    import simplejson as json\n    has_simplejson = True\nexcept ImportError:\n    import json\n    has_simplejson = False\n\n"
            "if has_simplejson:\n    from simplejson import JSONDecodeError\n\n"
            "if DEBUG:\n    import ujson\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = []\n')
            (ws / "app").mkdir()
            (ws / "app" / "compat.py").write_text(src)
            found = [f.message.split("'")[1] for f in scan_file_dependencies(ws / "app/compat.py", src, ws, load_declared_dependencies(ws))]
        self.assertEqual(found, ["ujson"])


class Bola(unittest.TestCase):
    def test_fastapi_annotated_guard_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "app").mkdir()
            (ws / "app" / "deps.py").write_text(
                "from typing import Annotated\nfrom fastapi import Depends\n"
                "CurrentUser = Annotated[User, Depends(get_current_user)]\n"
            )
            (ws / "app" / "items.py").write_text(
                "from fastapi import APIRouter\nfrom app.deps import CurrentUser\nrouter = APIRouter()\n\n"
                "@router.get('/items/{id}')\ndef read_item(session: SessionDep, current_user: CurrentUser, id: str):\n"
                "    item = session.get(Item, id)\n    if item.owner_id != current_user.id:\n        raise Forbidden()\n    return item\n\n"
                "@router.get('/notes/{id}')\ndef read_note(session: SessionDep, id: str):\n    return session.get(Note, id)\n"
            )
            with redirect_stdout(io.StringIO()):
                found = run_static_matrix_audit(ws)
        self.assertEqual(sorted((f.endpoint_or_file, f.line) for f in found if f.rule_id == "static-bola-unscoped-access"),
                         [("app/items.py", 12)])

    def test_use_server_scan_is_linear_and_still_finds_the_directive(self):
        banner = "/" * 60 + "\n"
        start = time.monotonic()
        self.assertFalse(_starts_with_use_server(banner * 40 + "export const x = 1;\n"))
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertTrue(_starts_with_use_server(banner * 3 + "/* note */\n\n'use server';\nexport async function f() {}\n"))
        self.assertFalse(_starts_with_use_server("export const x = 1;\n'use server';\n"))


if __name__ == "__main__":
    unittest.main()
