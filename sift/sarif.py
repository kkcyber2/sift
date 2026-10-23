"""SARIF 2.1.0 output.

Emitting real SARIF means the findings land in GitHub code scanning, VS Code and
any other consumer without a bespoke integration. The schema is strict, so this
module keeps the document minimal and validates the parts consumers actually read.
"""
from __future__ import annotations

import json
from typing import Sequence

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

RULE_ID = "SIFT-SSTI-001"

RULE = {
    "id": RULE_ID,
    "name": "ServerSideTemplateInjection",
    "shortDescription": {"text": "Server-side template injection"},
    "fullDescription": {
        "text": (
            "A user-controlled value reached a template engine's evaluation "
            "context. An attacker can run expressions in the engine's language "
            "and, where the sandbox permits it, reach the host."
        )
    },
    "helpUri": "https://owasp.org/www-project-web-security-testing-guide/",
    "defaultConfiguration": {"level": "error"},
    "properties": {"tags": ["security", "injection", "ssti"]},
}

# SARIF levels come from the finding's severity (about the vulnerability), not
# from attribution confidence -- a confirmed evaluation is an error even when we
# cannot yet name the engine.
LEVEL_BY_SEVERITY = {"error": "error", "warning": "warning", "note": "note"}


def build(
    findings: Sequence[dict],
    target: str,
    tool_version: str = "1.0.0",
) -> dict:
    """Turn sift findings into a SARIF log."""
    results = []
    for f in findings:
        payloads = ", ".join(e["payload"] for e in f.get("evidence", []))
        results.append(
            {
                "ruleId": RULE_ID,
                "level": LEVEL_BY_SEVERITY.get(f.get("severity", "warning"), "warning"),
                "message": {
                    "text": (
                        f"{f['engine_label']} evaluated injected expressions "
                        f"({f['hits']}/{f['probes']} probes, {f['confidence']} confidence). "
                        f"Confirmed payloads: {payloads or 'n/a'}."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target},
                        }
                    }
                ],
                "properties": {
                    "engine": f["engine"],
                    "confidence": f["confidence"],
                    "hits": f["hits"],
                    "probes": f["probes"],
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sift",
                        "version": tool_version,
                        "informationUri": "https://github.com/kkcyber2/sift",
                        "rules": [RULE],
                    }
                },
                "results": results,
            }
        ],
    }


def dumps(log: dict) -> str:
    return json.dumps(log, indent=2, sort_keys=False) + "\n"
