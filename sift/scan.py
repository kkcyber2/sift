"""Request planning and differential analysis.

The scanner is deliberately conservative:

* it only ever sends GET requests with the payload in one query parameter,
* it always sends a **control** request with a harmless value first, so a 500 or a
  page that happens to contain "49" cannot be mistaken for an evaluation,
* it never sends a sandbox-escape payload unless explicitly asked, because those
  are the payloads that actually execute code.

Everything here is pure functions over `Probe`/`Response` -- no sockets -- so the
whole decision logic is testable without a target.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .engines import ARITHMETIC_PROBES, ENGINES, Engine, classify, rank_engines


@dataclass(frozen=True)
class Response:
    status: int
    body: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400


@dataclass(frozen=True)
class Probe:
    """One request we intend to make."""

    engine: str
    payload: str          # raw expression, already wrapped in the dialect
    marker: str           # what we expect back if it evaluated
    raw: str              # the unwrapped expression, for the report
    discriminator: bool = False   # does the answer depend on the engine's language?


CONTROL_PAYLOAD = "sift7x7control"
CONTROL_MARKER = "7*7"


def build_probes(
    engines: Sequence[Engine] = ENGINES,
    probes: Sequence[tuple[str, str, bool]] = ARITHMETIC_PROBES,
) -> list[Probe]:
    """
    Expand each (engine, expression) pair into a concrete payload.

    Expressions the engine cannot evaluate are skipped entirely rather than being
    probed with a wrong expectation -- asking Twig for 7777777 and treating the
    "49" it correctly returns as a miss would be noise, not a signal.
    """
    out: list[Probe] = []
    for engine in engines:
        for expr, _note, discriminator in probes:
            expected = engine.semantics.get(expr)
            if expected is None:
                continue
            out.append(
                Probe(
                    engine=engine.key,
                    payload=engine.render(expr),
                    marker=expected,
                    raw=expr,
                    discriminator=discriminator,
                )
            )
    return out


def is_reflected(control: Response, test: Response, raw: str) -> bool:
    """
    True when the test response is indistinguishable from the control.

    A target that reflects our input back unchanged has not evaluated anything,
    and a target that returns identical bytes for a probe and a control value is
    not templating at all.
    """
    if not control.ok or not test.ok:
        return False
    if control.body == test.body:
        return True
    return False


def evaluate(
    responses: Sequence[tuple[Probe, Response]],
    controls: dict[str, Response],
) -> list[tuple[Probe, Response, bool]]:
    """
    Pair probes with a verdict.

    A probe counts as a hit only when:
      * the control for that probe's path was a healthy response, and
      * the test response differs from the control, and
      * the expected marker appears without the raw template being echoed.
    """
    out: list[tuple[Probe, Response, bool]] = []
    for probe, resp in responses:
        control = controls.get(probe.engine)
        if control is None or not control.ok:
            out.append((probe, resp, False))
            continue
        if is_reflected(control, resp, probe.raw):
            out.append((probe, resp, False))
            continue
        fp = classify(_engine(probe.engine), resp.body, probe.marker, probe.payload)
        out.append((probe, resp, fp.matched))
    return out


def _engine(key: str) -> Engine:
    for e in ENGINES:
        if e.key == key:
            return e
    raise KeyError(key)


def confidence(hits: int, total: int) -> str:
    """Three honest buckets rather than a fake percentage."""
    if total <= 0:
        return "none"
    ratio = hits / total
    if ratio >= 0.6:
        return "high"
    if ratio >= 0.25:
        return "medium"
    return "low"


def summarize(
    verdicts: Sequence[tuple[Probe, Response, bool]],
) -> list[dict]:
    """
    Collapse per-probe verdicts into one finding per engine.

    Detection and identification are deliberately separate:

    * "templating happened" is proven by the baseline probes, which every engine
      answers the same way;
    * "it is *this* engine" is proven only by the discriminator probes, whose
      answers differ between languages.

    Engines are therefore ranked by how many discriminators they got right, not by
    raw hit count. Without that split, Jinja2, Twig, Nunjucks and Handlebars all
    score 5/5 on baseline arithmetic and we would report four engines with equal
    confidence, which is useless to a human reading the report.
    """
    per_engine: dict[str, list[tuple[Probe, Response, bool]]] = {}
    for probe, resp, hit in verdicts:
        per_engine.setdefault(probe.engine, []).append((probe, resp, hit))

    findings: list[dict] = []
    for engine_key, rows in per_engine.items():
        hits = sum(1 for _p, _r, h in rows if h)
        if hits == 0:
            continue
        # A finding needs at least one *baseline* hit. Discriminator-only hits
        # mean an expression matched by coincidence, not that templating ran.
        if not any(h for p, _r, h in rows if not p.discriminator):
            continue

        disc = [(p, r, h) for p, r, h in rows if p.discriminator]
        disc_hits = sum(1 for _p, _r, h in disc if h)
        engine = _engine(engine_key)

        # A finding needs the baseline to fire, and its confidence comes from the
        # discriminators: a generic "something renders templates" result is not
        # worth calling high confidence.
        if disc:
            conf = confidence(disc_hits, len(disc))
            # An engine that produced no discriminators at all is only ever
            # "something rendered" -- never call that high confidence.
            if disc_hits == 0:
                conf = "medium" if conf == "high" else conf
        else:  # pragma: no cover - every engine has discriminators today
            conf = "medium"

        findings.append(
            {
                "engine": engine_key,
                "engine_label": engine.label,
                "hits": hits,
                "probes": len(rows),
                "discriminator_hits": disc_hits,
                "discriminator_probes": len(disc),
                "confidence": conf,
                # Severity is about the vulnerability, confidence is about the
                # attribution. Confirmed template evaluation is always an error;
                # we simply may not be sure which engine we are looking at.
                "severity": "error" if conf in ("high", "medium") else "warning",
                "evidence": [
                    {
                        "payload": p.payload,
                        "expected": p.marker,
                        "status": r.status,
                        "discriminator": p.discriminator,
                        "excerpt": r.body[:160],
                    }
                    for p, r, h in rows
                    if h
                ],
                "sandbox_escape_payloads": list(engine.sandbox_escapes),
                "notes": engine.notes,
            }
        )

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(
        key=lambda f: (
            order[f["confidence"]],
            -f["discriminator_hits"],
            -f["hits"],
            f["engine"],
        )
    )

    # Exactly one engine gets called the likely match; the rest are retained as
    # "also evaluated" context so nothing is hidden from the operator.
    for rank, f in enumerate(findings):
        f["likely"] = rank == 0

    return findings


def likely_engine(findings: Sequence[dict]) -> str | None:
    """The single best-supported engine key, or None."""
    for f in findings:
        if f.get("likely"):
            return f["engine"]
    return None


def ranked(fingerprints) -> list[tuple[str, int]]:
    """Re-exported for callers that only have raw fingerprints."""
    return rank_engines(list(fingerprints))
