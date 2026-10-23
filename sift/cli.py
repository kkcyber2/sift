"""Command line interface.

    sift scan URL --param q [--json] [--sarif out.sarif] [--engines jinja2,twig]

Exit codes are meant for CI: 0 clean, 1 findings, 2 usage/target error.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import sarif
from .engines import BY_KEY, ENGINES
from .scan import build_probes, evaluate, likely_engine, summarize
from .transport import probe


def _engines_from(spec: str | None):
    if not spec:
        return ENGINES
    keys = [k.strip() for k in spec.split(",") if k.strip()]
    unknown = [k for k in keys if k not in BY_KEY]
    if unknown:
        raise SystemExit(f"unknown engine(s): {', '.join(unknown)}")
    return tuple(BY_KEY[k] for k in keys)


def cmd_engines(_args) -> int:
    print(f"{'key':<12} {'label':<14} {'delimiters':<14} notes")
    print("-" * 96)
    for e in ENGINES:
        print(f"{e.key:<12} {e.label:<14} {e.expr:<14} {e.notes}")
    print(f"\n{len(ENGINES)} engines, "
          f"{sum(len(e.sandbox_escapes) for e in ENGINES)} curated escape payloads.")
    return 0


def cmd_scan(args) -> int:
    engines = _engines_from(args.engines)

    # 1. Control: a value that must never evaluate to anything.
    control = probe(args.url, args.param, args.control)
    if control.status == 0:
        print(f"sift: could not reach {args.url}", file=sys.stderr)
        return 2

    # 2. One control per engine so a page that always contains "49" is caught.
    controls = {}
    for engine in engines:
        controls[engine.key] = probe(args.url, args.param, engine.render(args.control))

    # 3. The real probes.
    rows = []
    for p in build_probes(engines):
        rows.append((p, probe(args.url, args.param, p.payload)))

    verdicts = evaluate(rows, controls)
    findings = summarize(verdicts)

    best = likely_engine(findings)

    if args.json:
        print(json.dumps({
            "target": args.url,
            "param": args.param,
            "likely_engine": best,
            "findings": findings,
        }, indent=2))
    else:
        if not findings:
            print(f"no template injection found at {args.url}?{args.param}=")
            print(f"  ({len(rows)} probes across {len(engines)} engines, all negative)")
        else:
            top = findings[0]
            print(f"VULNERABLE — {top['engine_label']} "
                  f"({top['confidence']} confidence, "
                  f"{top['discriminator_hits']}/{top['discriminator_probes']} discriminators)")
            print(f"  {args.url}?{args.param}=")
            print(f"  {len(findings)} engine dialect(s) evaluated the payload; "
                  f"best match above.\n")
            for f in findings:
                mark = "->" if f["likely"] else "  "
                print(f" {mark} [{f['confidence'].upper():<6}] {f['engine_label']:<12} "
                      f"{f['hits']}/{f['probes']} probes, "
                      f"{f['discriminator_hits']}/{f['discriminator_probes']} discriminators")
                if f["likely"]:
                    for ev in f["evidence"][:4]:
                        tag = "discriminator" if ev["discriminator"] else "baseline"
                        print(f"      {ev['payload']}  =>  {ev['expected']}   ({tag})")
                    print(f"      {f['notes']}")
                print()

    if args.sarif:
        log = sarif.build(findings, args.url)
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(sarif.dumps(log))
        print(f"SARIF written to {args.sarif}", file=sys.stderr)

    # 1 means "findings present" so CI can gate on it.
    return 1 if findings else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sift", description="Server-side template injection scanner")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a URL parameter for template injection")
    s.add_argument("url")
    s.add_argument("--param", default="q", help="query parameter to inject (default: q)")
    s.add_argument("--engines", default=None, help="comma-separated engine keys")
    s.add_argument("--control", default="sift7x7control", help="harmless control value")
    s.add_argument("--json", action="store_true")
    s.add_argument("--sarif", default=None, metavar="PATH")
    s.set_defaults(func=cmd_scan)

    e = sub.add_parser("engines", help="list supported engines")
    e.set_defaults(func=cmd_engines)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
