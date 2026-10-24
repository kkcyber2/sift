"""Tests for the detection logic.

The scanning pipeline is pure by design, so almost everything here runs without a
socket. The one integration test starts a real HTTP server that *actually* evaluates
Jinja2, which is the only way to prove the differential logic works end to end.
"""
from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sift import sarif
from sift.engines import ARITHMETIC_PROBES, ENGINES, BY_KEY, classify, rank_engines
from sift.scan import (
    Probe,
    Response,
    build_probes,
    confidence,
    evaluate,
    is_reflected,
    summarize,
)
from sift.transport import build_url


# --------------------------------------------------------------------- engines
def test_engine_keys_are_unique():
    keys = [e.key for e in ENGINES]
    assert len(keys) == len(set(keys))


def test_every_engine_has_a_wrapper_and_escapes():
    for e in ENGINES:
        assert "EXPR" in e.expr, f"{e.key} has no EXPR placeholder"
        assert e.true_render, f"{e.key} has no boolean rendering"
        assert e.notes, f"{e.key} has no note"
        assert e.sandbox_escapes, f"{e.key} has no escape payloads"


def test_engine_render_substitutes_the_expression():
    j = BY_KEY["jinja2"]
    assert j.render("7*7") == "{{ 7*7 }}"
    assert j.render("8*8") == "{{ 8*8 }}"
    # no stray placeholder left behind
    assert "EXPR" not in j.render("1+1")


def test_engine_render_does_not_mutate_the_template():
    t = BY_KEY["erb"]
    before = t.expr
    t.render("7*7")
    assert t.expr == before


# ---------------------------------------------------------------- fingerprinting
def test_classify_detects_evaluation():
    fp = classify(BY_KEY["jinja2"], "<html>Result: 49</html>")
    assert fp.matched is True
    assert fp.reason == "evaluated"


def test_classify_rejects_reflection():
    fp = classify(BY_KEY["jinja2"], "<html>{{ 7*7 }}</html>")
    assert fp.matched is False


def test_classify_rejects_error_pages_quoting_the_input():
    """An error page echoes the payload *and* may mention 49. That is not proof."""
    body = "TemplateSyntaxError: cannot parse {{ 7*7 }} near '49'"
    fp = classify(BY_KEY["jinja2"], body, "49")
    assert fp.matched is False
    assert "echoed" in fp.reason


def test_classify_requires_the_expected_marker():
    fp = classify(BY_KEY["jinja2"], "<html>Result: 48</html>", "49")
    assert fp.matched is False


def test_rank_engines_orders_by_agreement():
    from sift.engines import Fingerprint

    fps = [
        Fingerprint("jinja2", True, "", "49"),
        Fingerprint("jinja2", True, "", "64"),
        Fingerprint("twig", True, "", "49"),
        Fingerprint("erb", False, "", "49"),
    ]
    ranked = rank_engines(fps)
    assert ranked[0] == ("jinja2", 2)
    assert ("erb", 1) not in ranked
    assert ("twig", 1) in ranked


# ------------------------------------------------------------------ probe design
def test_build_probes_covers_every_engine():
    probes = build_probes()
    engines_seen = {p.engine for p in probes}
    assert engines_seen == {e.key for e in ENGINES}
    assert len(probes) == sum(len(e.semantics) for e in ENGINES)


def test_build_probes_skips_expressions_an_engine_cannot_evaluate():
    probes = build_probes()
    by_engine = {}
    for p in probes:
        by_engine.setdefault(p.engine, set()).add(p.raw)
    # Twig has no ** operator, so it must not be probed for 2**5 at all.
    assert "2**5" not in by_engine["twig"]
    # Jinja2 has no ~ concatenation operator.
    assert "'a'~'b'" not in by_engine["jinja2"]
    assert "'a'~'b'" in by_engine["twig"]


def test_each_probe_carries_its_own_engine_expectation():
    """A probe's marker must come from the engine, not from a shared table."""
    from sift.engines import BY_KEY
    for p in build_probes():
        assert p.marker == BY_KEY[p.engine].semantics[p.raw]


def test_twig_and_jinja2_disagree_about_string_repetition():
    from sift.engines import BY_KEY
    assert BY_KEY["jinja2"].semantics["7*'7'"] == "7777777"
    assert BY_KEY["twig"].semantics["7*'7'"] == "49"


def test_build_probes_payloads_are_wrapped():
    for p in build_probes():
        assert p.raw in p.payload
        assert p.payload != p.raw, "payload must include the engine's delimiters"


def test_probes_include_the_string_repetition_canary():
    """7*'7' is the classic engine discriminator: 49 vs 7777777."""
    probes = build_probes()
    raws = {p.raw for p in probes}
    assert "7*'7'" in raws
    assert "7.0*7" in raws


# ------------------------------------------------------------------- reflection
def test_identical_control_and_test_is_not_a_hit():
    ctrl = Response(200, "<html>hello</html>")
    test = Response(200, "<html>hello</html>")
    assert is_reflected(ctrl, test, "7*7") is True


def test_differing_bodies_are_not_reflected():
    ctrl = Response(200, "<html>hello</html>")
    test = Response(200, "<html>49</html>")
    assert is_reflected(ctrl, test, "7*7") is False


def test_failed_control_disables_the_probe():
    ctrl = Response(500, "")
    test = Response(200, "49")
    assert is_reflected(ctrl, test, "7*7") is False


# ------------------------------------------------------------------- evaluation
def _pair(engine="jinja2", marker="49", raw="7*7", discriminator=False):
    p = Probe(
        engine=engine,
        payload=f"{{{{ {raw} }}}}",
        marker=marker,
        raw=raw,
        discriminator=discriminator,
    )
    return p


def test_evaluate_marks_a_real_evaluation_as_a_hit():
    p = _pair()
    controls = {"jinja2": Response(200, "<html>sift7x7control</html>")}
    verdicts = evaluate([(p, Response(200, "<html>49</html>"))], controls)
    assert verdicts[0][2] is True


def test_evaluate_rejects_a_reflected_payload():
    p = _pair()
    controls = {"jinja2": Response(200, "<html>{ 7*7 }</html>")}
    verdicts = evaluate([(p, Response(200, "<html>{ 7*7 }</html>"))], controls)
    assert verdicts[0][2] is False


def test_evaluate_without_a_control_is_a_miss():
    p = _pair()
    verdicts = evaluate([(p, Response(200, "49"))], {})
    assert verdicts[0][2] is False


def test_evaluate_when_control_errored_is_a_miss():
    p = _pair()
    controls = {"jinja2": Response(503, "")}
    verdicts = evaluate([(p, Response(200, "49"))], controls)
    assert verdicts[0][2] is False


# -------------------------------------------------------------------- summarize
def test_summarize_groups_by_engine_and_scores():
    rows = [
        (_pair("jinja2", "49", "7*7"), Response(200, "49"), True),
        (_pair("jinja2", "64", "8*8"), Response(200, "64"), True),
        (_pair("jinja2", "49.0", "7.0*7", discriminator=True), Response(200, "49.0"), True),
        (_pair("jinja2", "7777777", "7*'7'", discriminator=True), Response(200, "7777777"), True),
        (_pair("twig", "49", "7*7"), Response(200, "control"), False),
    ]
    findings = summarize(rows)
    assert len(findings) == 1
    f = findings[0]
    assert f["engine"] == "jinja2"
    assert f["hits"] == 4
    assert f["probes"] == 4
    assert f["discriminator_hits"] == 2
    assert f["discriminator_probes"] == 2
    assert f["confidence"] == "high"
    assert f["likely"] is True
    assert len(f["evidence"]) == 4


def test_summarize_drops_engines_with_no_hits():
    rows = [(_pair("twig"), Response(200, "control"), False)]
    assert summarize(rows) == []


def test_summarize_flags_a_single_hit_as_low_confidence():
    rows = [(_pair("jinja2"), Response(200, "49"), True)]
    for i in range(4):
        rows.append((_pair("jinja2", f"x{i}", "1+1", discriminator=True),
                     Response(200, "control"), False))
    findings = summarize(rows)
    assert findings[0]["confidence"] == "low"
    assert findings[0]["hits"] == 1
    assert findings[0]["discriminator_hits"] == 0


def test_confidence_buckets():
    assert confidence(0, 5) == "low"
    assert confidence(3, 5) == "high"
    assert confidence(2, 5) == "medium"
    assert confidence(1, 10) == "low"
    assert confidence(0, 0) == "none"


def test_findings_are_sorted_high_confidence_first():
    rows = []
    for i in range(5):
        rows.append((_pair("jinja2", "49", f"7*{i}", discriminator=True),
                     Response(200, "49"), True))
    rows.append((_pair("jinja2", "49", "7+0"), Response(200, "49"), True))
    for i in range(5):
        rows.append((_pair("erb", "49", f"8*{i}", discriminator=True),
                     Response(200, "49"), i == 0))
    rows.append((_pair("erb", "49", "8+0"), Response(200, "49"), True))
    findings = summarize(rows)
    assert findings[0]["engine"] == "jinja2"
    assert findings[0]["confidence"] == "high"
    assert findings[1]["confidence"] == "low"
    assert findings[0]["likely"] is True
    assert findings[1]["likely"] is False


def test_only_one_engine_is_marked_likely():
    rows = []
    for eng in ("jinja2", "twig", "erb"):
        rows.append((_pair(eng, "49", "7*7"), Response(200, "49"), True))
    findings = summarize(rows)
    assert sum(1 for f in findings if f["likely"]) == 1


def test_discriminators_rank_jinja2_above_twig_on_a_jinja2_target():
    """The whole point: baseline arithmetic cannot tell these apart, so the
    discriminators must decide."""
    rows = []
    # both engines answer baseline arithmetic identically
    for eng in ("jinja2", "twig"):
        rows.append((_pair(eng, "49", "7*7"), Response(200, "49"), True))
        rows.append((_pair(eng, "64", "8*8"), Response(200, "64"), True))
    # only Jinja2 repeats strings and true-divides the Python way
    rows.append((_pair("jinja2", "7777777", "7*'7'", discriminator=True),
                 Response(200, "7777777"), True))
    rows.append((_pair("jinja2", "2.5", "5/2", discriminator=True),
                 Response(200, "2.5"), True))
    rows.append((_pair("twig", "7777777", "7*'7'", discriminator=True),
                 Response(200, "49"), False))
    rows.append((_pair("twig", "2.5", "5/2", discriminator=True),
                 Response(200, "2.5"), True))
    findings = summarize(rows)
    assert findings[0]["engine"] == "jinja2"
    assert findings[0]["discriminator_hits"] == 2
    assert findings[1]["discriminator_hits"] == 1
    from sift.scan import likely_engine
    assert likely_engine(findings) == "jinja2"


def test_findings_carry_escape_payloads_for_the_reporter():
    rows = [(_pair("jinja2"), Response(200, "49"), True)]
    f = summarize(rows)[0]
    assert f["sandbox_escape_payloads"]
    assert all(isinstance(s, str) for s in f["sandbox_escape_payloads"])


# ----------------------------------------------------------------------- SARIF
def test_sarif_document_is_valid_and_well_formed():
    findings = summarize([
        (_pair("jinja2", "49", "7*7"), Response(200, "49"), True),
        (_pair("jinja2", "7777777", "7*'7'", discriminator=True),
         Response(200, "7777777"), True),
    ])
    log = sarif.build(findings, "https://example.test/search?q=1")
    assert log["version"] == "2.1.0"
    assert log["$schema"].startswith("https://")
    assert len(log["runs"]) == 1
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "sift"
    assert len(run["results"]) == 1

    result = run["results"][0]
    assert result["ruleId"] == sarif.RULE_ID
    assert result["level"] == "error"
    assert "Jinja2" in result["message"]["text"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("https://")


def test_sarif_serialises_to_json():
    findings = summarize([(_pair("jinja2"), Response(200, "49"), True)])
    text = sarif.dumps(sarif.build(findings, "https://example.test/"))
    parsed = json.loads(text)
    assert parsed["version"] == "2.1.0"


def test_sarif_with_no_findings_is_still_valid():
    log = sarif.build([], "https://example.test/")
    assert log["runs"][0]["results"] == []


def test_sarif_level_follows_severity_not_attribution_confidence():
    """A confirmed evaluation is an error even if we cannot name the engine."""
    high = summarize([
        (_pair("jinja2", "49", "7*7"), Response(200, "49"), True),
        (_pair("jinja2", "7777777", "7*'7'", discriminator=True),
         Response(200, "7777777"), True),
    ])
    unknown = summarize([(_pair("twig"), Response(200, "49"), True)])
    assert sarif.build(high, "u")["runs"][0]["results"][0]["level"] == "error"
    assert sarif.build(unknown, "u")["runs"][0]["results"][0]["level"] == "error"
    assert sarif.build(unknown, "u")["runs"][0]["results"][0]["properties"]["confidence"] != "high"


# ------------------------------------------------------------------- URL building
def test_build_url_adds_a_parameter():
    url = build_url("https://example.test/search?x=1", "q", "{{7*7}}")
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert q["x"] == ["1"]
    assert q["q"] == ["{{7*7}}"]


def test_build_url_replaces_an_existing_parameter():
    url = build_url("https://example.test/s?q=old&z=2", "q", "new")
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert q["q"] == ["new"]
    assert q["z"] == ["2"]
    assert url.count("q=") == 1


def test_build_url_rejects_non_http_schemes():
    for bad in ("file:///etc/passwd", "ftp://x/", "javascript:alert(1)"):
        with pytest.raises(ValueError):
            build_url(bad, "q", "x")


def test_build_url_encodes_payloads_safely():
    url = build_url("https://example.test/", "q", "{{ 7*7 }}&evil=1")
    assert "&evil=1" not in url.split("q=")[1]
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert "evil" not in q


# ------------------------------------------------------- end-to-end over HTTP
class _VulnerableHandler(BaseHTTPRequestHandler):
    """Renders the q parameter through Jinja2 for real."""

    def do_GET(self):  # noqa: N802
        try:
            import jinja2
        except ImportError:  # pragma: no cover - only on a bare install
            self.send_error(503, "jinja2 unavailable")
            return

        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        raw = qs.get("q", [""])[0]
        try:
            rendered = jinja2.Template(raw).render()
        except Exception as exc:  # noqa: BLE001
            rendered = f"error: {exc}"
        body = f"<html><body>result: {rendered}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class _SafeHandler(BaseHTTPRequestHandler):
    """Reflects the parameter without evaluating it."""

    def do_GET(self):  # noqa: N802
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        raw = qs.get("q", [""])[0]
        body = f"<html><body>you searched for: {raw}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def _has_jinja2() -> bool:
    try:
        import jinja2  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.fixture
def server(request):
    handler = getattr(request, "param", _VulnerableHandler)
    if handler is _VulnerableHandler and not _has_jinja2():
        pytest.skip("jinja2 not installed: cannot stand up the vulnerable fixture")
    srv = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_port}/"
    srv.shutdown()
    srv.server_close()


@pytest.mark.parametrize("server", [_VulnerableHandler], indirect=True)
def test_end_to_end_finds_jinja2_on_a_real_vulnerable_server(server):
    from sift.cli import main

    assert main(["scan", server, "--param", "q"]) == 1


@pytest.mark.parametrize("server", [_SafeHandler], indirect=True)
def test_end_to_end_reports_clean_on_a_reflecting_server(server):
    from sift.cli import main

    assert main(["scan", server, "--param", "q"]) == 0


@pytest.mark.parametrize("server", [_SafeHandler], indirect=True)
def test_end_to_end_json_output_is_parseable(server, capsys):
    from sift.cli import main

    main(["scan", server, "--param", "q", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["findings"] == []
    assert payload["param"] == "q"


@pytest.mark.parametrize("server", [_VulnerableHandler], indirect=True)
def test_end_to_end_writes_sarif(server, tmp_path):
    from sift.cli import main

    out = tmp_path / "sift.sarif"
    main(["scan", server, "--param", "q", "--sarif", str(out)])
    assert out.exists()
    log = json.loads(out.read_text())
    assert log["runs"][0]["results"]


def test_cli_rejects_unknown_engine():
    from sift.cli import main

    with pytest.raises(SystemExit):
        main(["scan", "https://example.test/", "--engines", "not-an-engine"])


def test_cli_unreachable_target_returns_2():
    from sift.cli import main

    # port 1 on loopback: connection refused, fast
    assert main(["scan", "http://127.0.0.1:1/", "--param", "q"]) == 2
