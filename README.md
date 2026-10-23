# sift

A server-side template injection scanner that tells you **which** engine you are
looking at, not just that something evaluated your payload.

```
$ sift scan https://target.example/search --param q
VULNERABLE — Jinja2 (high confidence, 5/5 discriminators)
  4 engine dialect(s) evaluated the payload; best match above.

 -> [HIGH  ] Jinja2       7/7 probes, 5/5 discriminators
      {{ 7*7 }}  =>  49   (baseline)
      {{ 7*'7' }}  =>  7777777   (discriminator)
```

## Why this exists

Most SSTI scanners send `{{7*7}}`, see `49`, and report "template injection". That
is enough to know a bug exists and not nearly enough to exploit or fix it: the
next step depends entirely on the engine. Jinja2, Twig, Nunjucks, Handlebars and
Pug all accept `{{ }}`, and all of them return `49` for `{{7*7}}`.

sift separates the two questions.

**Did templating happen?** Baseline probes — arithmetic every engine answers.

**Which engine?** Discriminator probes — expressions whose *answer depends on the
language*. `7*'7'` is `7777777` in Python and Ruby, and `49` in PHP. `5/2` is
`2.5` in Python, PHP and JS, and `2` in Java and Ruby. `2**5` is a syntax error
in Twig. Each engine declares what *it* renders (`Engine.semantics`), so an answer
only confirms a language that actually predicts it.

Nine engines, 51 probes, 19 curated escape payloads.

## Install

```bash
pip install -e .
```

Python 3.10+. `pytest` for the tests. No network access at import time.

## Usage

```bash
sift engines                                   # what's supported
sift scan https://target.example/s --param q   # human output
sift scan ... --json                           # machine output
sift scan ... --sarif out.sarif                # GitHub code scanning
sift scan ... --engines jinja2,twig            # narrow the search
```

Exit codes: `0` clean, `1` findings (gate CI on this), `2` unreachable or bad usage.

## How it decides

Every probe is compared against a **control** request for the same engine, so a
page that happens to contain `49` cannot be mistaken for an evaluation. On top of
that:

- the echoed payload is **removed from the body before matching**, so a reflected
  `#set($x=5/2)$x` cannot satisfy the marker `2` by containing it;
- a finding requires at least one **baseline** hit — discriminators alone mean a
  coincidence, not templating;
- confidence comes from **discriminator agreement**, and an engine with zero
  discriminators is never called high confidence;
- exactly one engine is marked `likely`; the others are kept as context.

## Scope and safety

A tool that sends payloads to arbitrary hosts is a liability, so the transport is
the narrowest thing that works:

- GET requests only, payload in one query parameter;
- redirects are followed **only** while they stay on the original host;
- non-`http(s)` schemes are refused;
- sandbox-escape payloads are reported as suggestions for the operator, **never
  sent** — sending those executes code, which is a different decision.

Only scan systems you are authorised to test.

## Output

SARIF 2.1.0 (`--sarif`) drops straight into GitHub code scanning and VS Code.
Severity follows the vulnerability — a confirmed evaluation is always an `error` —
while `confidence` describes how sure the *attribution* is. Those are different
questions and conflating them produces reports nobody trusts.

## Tests

```bash
python -m pytest tests/ -q     # 44 tests
```

The suite includes two real HTTP servers: one that genuinely renders Jinja2 and
one that only reflects. The first must produce a Jinja2 finding; the second must
produce nothing.

## License

MIT — see [LICENSE](LICENSE).

---

Built by **KK (Conan Sultan Khan)** · [github.com/kkcyber2](https://github.com/kkcyber2) · kkdev9715@gmail.com
