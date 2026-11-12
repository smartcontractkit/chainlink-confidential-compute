#!/usr/bin/env python3
"""Generate and refresh mermaid diagrams from source code via a chat completions API.

Diagrams are declared in a manifest (default `.github/diagrams.yaml`). Each entry
names its source files, the prompt describing what to draw, and where the result
goes. A digest of the resolved sources is stored alongside the rendered block, so
a diagram is only regenerated when the code it describes actually changes.

  gen_diagrams.py                  refresh every stale diagram
  gen_diagrams.py --check          exit 3 if any diagram is stale, write nothing
  gen_diagrams.py --only <id>...   restrict to the named diagrams
  gen_diagrams.py --force          regenerate even when the digest matches

The model endpoint is supplied entirely through the environment, so no provider
or model name appears in this repository:

  LLM_API_URL    chat completions endpoint (OpenAI-compatible)
  LLM_MODEL      model identifier to request
  LLM_API_KEY    bearer token

This file is kept byte-identical across confidential-compute,
confidential-compute-infra and confidential-compute-scripts. Repo-specific
configuration belongs in the manifest.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import yaml

DEFAULT_BUDGET_CHARS = 320_000
DEFAULT_MAX_TOKENS = 65536
DEFAULT_ATTEMPTS = 3
DEFAULT_JOBS = 4
# Each mermaid render launches a headless Chromium, so cap those independently
# of the API calls, which are only waiting on the network.
MAX_CONCURRENT_RENDERS = 2

BEGIN = "<!-- diagram:BEGIN id={id} digest={digest} -->"
END = "<!-- diagram:END id={id} -->"
BEGIN_RE = r"<!--\s*diagram:BEGIN id={id} digest=(?P<digest>[0-9a-f]*)\s*-->"
END_RE = r"<!--\s*diagram:END id={id}\s*-->"

# Any managed block, whatever its id. Stripped from markdown sources so a
# generated block never feeds back into its own digest.
ANY_BLOCK_RE = re.compile(
    r"\n*<!--\s*diagram:BEGIN id=\S+ digest=[0-9a-f]*\s*-->.*?"
    r"<!--\s*diagram:END id=\S+\s*-->\n*",
    re.DOTALL,
)

SYSTEM_PROMPT = """\
You are a staff engineer documenting a production system with mermaid diagrams.

You will be given source files and a description of one diagram to produce.

Rules:
- Reply with exactly one mermaid code block and nothing else. No preamble, no
  explanation, no prose after the block.
- The diagram must describe only what the supplied sources actually show. Do not
  invent components, ports, protocols or steps. If the sources are inconclusive
  about a detail, leave the detail out rather than guessing.
- Prefer concrete identifiers from the code (type names, function names, env
  vars, chart values, ports, hostnames) over generic labels.
- Keep it legible: aim for 12-30 nodes. Group related nodes with subgraphs and
  collapse incidental detail rather than drawing every file.
- Node text must be quoted when it contains anything other than alphanumerics,
  spaces or underscores: A["host:10443 /execute"]. Never place unquoted
  parentheses, braces, slashes, colons, commas or hyphens in a label.
- Do not use <br> tags, HTML, markdown, emoji, `style`, `classDef`, `linkStyle`
  or `click` directives. Plain structural mermaid only.
- Edge labels use the -->|"label"| form with the label quoted.
"""


_local = threading.local()
PRINT_LOCK = threading.Lock()
RENDER_SEM = threading.Semaphore(MAX_CONCURRENT_RENDERS)


def log(msg: str) -> None:
    buf = getattr(_local, "buf", None)
    if buf is None:
        print(msg, file=sys.stderr, flush=True)
    else:
        buf.append(msg)


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #


@dataclass
class SourceGroup:
    paths: list[str]
    exclude: list[str] = field(default_factory=list)
    outline: bool = False
    label: str = ""


@dataclass
class Spec:
    id: str
    output: str
    title: str
    kind: str
    instructions: str
    sources: list[SourceGroup]
    budget_chars: int
    max_tokens: int
    reasoning_effort: str = ""


def load_manifest(path: Path, root: Path) -> tuple[list[Spec], dict]:
    raw = yaml.safe_load(path.read_text()) or {}
    defaults = {
        "budget_chars": int(raw.get("budget_chars", DEFAULT_BUDGET_CHARS)),
        "max_tokens": int(raw.get("max_output_tokens", DEFAULT_MAX_TOKENS)),
        "reasoning_effort": str(raw.get("reasoning_effort", "") or ""),
    }

    specs: list[Spec] = []
    for entry in raw.get("diagrams") or []:
        groups = []
        for g in entry.get("sources") or []:
            if isinstance(g, str):
                g = {"paths": [g]}
            groups.append(
                SourceGroup(
                    paths=list(g.get("paths") or []),
                    exclude=list(g.get("exclude") or []),
                    outline=bool(g.get("outline", False)),
                    label=str(g.get("label", "")),
                )
            )
        output = entry["output"]
        specs.append(
            Spec(
                id=entry["id"],
                output=output,
                title=entry.get("title", entry["id"]),
                kind=entry.get("kind", "flowchart"),
                instructions=entry.get("instructions", "").strip(),
                sources=groups,
                budget_chars=int(entry.get("budget_chars", defaults["budget_chars"])),
                max_tokens=int(entry.get("max_output_tokens", defaults["max_tokens"])),
                reasoning_effort=str(
                    entry.get("reasoning_effort", defaults["reasoning_effort"]) or ""
                ),
            )
        )
    return specs, defaults


# --------------------------------------------------------------------------- #
# Source resolution
# --------------------------------------------------------------------------- #

ALWAYS_EXCLUDE = ("**/*_test.go", "**/*.pb.go", "**/testdata/**", "**/vendor/**")


def resolve_group(group: SourceGroup, root: Path) -> list[Path]:
    excluded: set[Path] = set()
    for pattern in list(group.exclude) + list(ALWAYS_EXCLUDE):
        excluded.update(root.glob(pattern))

    found: list[Path] = []
    for pattern in group.paths:
        # Preserve manifest order; sort only within a single pattern so the
        # digest is stable regardless of filesystem iteration order.
        matches = sorted(p for p in root.glob(pattern) if p.is_file())
        for p in matches:
            if p not in excluded and p not in found:
                found.append(p)
    return found


def go_outline(text: str) -> str:
    """Reduce Go source to its package, imports and top-level declarations."""
    decl = re.compile(r"^(package|import|func|type|const|var)\b")
    lines = text.splitlines()
    kept: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not decl.match(line):
            i += 1
            continue

        # Pull in the doc comment attached to this declaration.
        j = len(kept)
        back = i - 1
        comment: list[str] = []
        while back >= 0 and lines[back].startswith("//"):
            comment.insert(0, lines[back])
            back -= 1
        kept.extend(comment[-3:])

        opens = line.count("{") + line.count("(") - line.count("}") - line.count(")")
        kept.append(line)
        if line.startswith("func") or opens <= 0:
            i += 1
            continue

        # Grouped or composite declaration: keep it until the braces balance.
        i += 1
        while i < len(lines) and opens > 0:
            body = lines[i]
            opens += body.count("{") + body.count("(")
            opens -= body.count("}") + body.count(")")
            kept.append(body)
            i += 1
        if len(kept) - j > 60:
            del kept[j + 60 :]
            kept.append("\t// ... truncated")
    return "\n".join(kept)


def normalize_markdown(text: str) -> str:
    """Strip managed blocks and flatten whitespace so a file hashes the same
    before and after a block is injected into it."""
    text = ANY_BLOCK_RE.sub("\n\n", text)
    text = "\n".join(line.rstrip() for line in text.splitlines())
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def read_source(path: Path, root: Path, outline: bool) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log(f"  ! unreadable {path}: {exc}")
        return ""
    if path.suffix == ".md":
        text = normalize_markdown(text)
    if outline:
        text = go_outline(text) if path.suffix == ".go" else "\n".join(text.splitlines()[:120])
    return text


def collect_sources(spec: Spec, root: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Return (path, content) pairs within budget, plus the paths dropped."""
    blobs: list[tuple[str, str]] = []
    for group in spec.sources:
        for path in resolve_group(group, root):
            text = read_source(path, root, group.outline)
            if text.strip():
                blobs.append((str(path.relative_to(root)), text))

    kept: list[tuple[str, str]] = []
    dropped: list[str] = []
    used = 0
    for rel, text in blobs:
        cost = len(text) + len(rel) + 32
        if used + cost > spec.budget_chars and kept:
            dropped.append(rel)
            continue
        kept.append((rel, text))
        used += cost
    return kept, dropped


def digest_for(spec: Spec, blobs: list[tuple[str, str]]) -> str:
    """Fingerprint of everything that should force a regeneration. Excludes the
    model id; use --force after a model change."""
    h = hashlib.sha256()
    h.update(b"v1\0")
    for part in (spec.id, spec.title, spec.kind, spec.instructions):
        h.update(part.encode() + b"\0")
    for rel, text in blobs:
        h.update(rel.encode() + b"\0")
        h.update(hashlib.sha256(text.encode()).digest())
    return h.hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Model API
# --------------------------------------------------------------------------- #


@dataclass
class Endpoint:
    """Where to send completions. Sourced from the environment, never the repo."""

    url: str
    model: str
    api_key: str

    @classmethod
    def from_env(cls) -> "Endpoint":
        missing = [v for v in ("LLM_API_URL", "LLM_MODEL", "LLM_API_KEY")
                   if not os.environ.get(v)]
        if missing:
            raise KeyError(", ".join(missing))
        return cls(
            url=os.environ["LLM_API_URL"],
            model=os.environ["LLM_MODEL"],
            api_key=os.environ["LLM_API_KEY"],
        )


def build_user_prompt(spec: Spec, blobs: list[tuple[str, str]], dropped: list[str]) -> str:
    parts = [
        f"# Diagram to produce: {spec.title}",
        "",
        f"Diagram type: `{spec.kind}`. Begin the mermaid block with this type.",
        "",
        "## What to show",
        "",
        spec.instructions,
        "",
        "## Sources",
        "",
    ]
    for rel, text in blobs:
        lang = {
            ".go": "go",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".tpl": "gotemplate",
            ".md": "markdown",
            ".sh": "bash",
            ".json": "json",
        }.get(Path(rel).suffix, "")
        parts += [f"### `{rel}`", "", f"```{lang}", text.rstrip(), "```", ""]
    if dropped:
        parts += [
            "### Omitted for length",
            "",
            "These files matched but did not fit the context budget. Do not "
            "speculate about their contents:",
            "",
            *(f"- `{p}`" for p in dropped),
            "",
        ]
    return "\n".join(parts)


def call_model(endpoint: "Endpoint", messages: list[dict], max_tokens: int,
               reasoning_effort: str = "") -> tuple[str, str]:
    request = {
        "model": endpoint.model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }
    if reasoning_effort:
        request["reasoning_effort"] = reasoning_effort
    body = json.dumps(request).encode()

    last: Exception | None = None
    for attempt in range(1, 5):
        req = urllib.request.Request(
            endpoint.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {endpoint.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                payload = json.load(resp)
            choice = payload["choices"][0]
            finish = choice.get("finish_reason") or ""
            if finish == "length":
                log("  ! response hit max_tokens; diagram may be truncated")
            usage = payload.get("usage") or {}
            log(
                f"  tokens: prompt={usage.get('prompt_tokens', '?')} "
                f"completion={usage.get('completion_tokens', '?')}"
            )
            message = choice.get("message") or {}
            content = strip_think(message.get("content") or "")
            if not content:
                # Reasoning models bill thinking against max_tokens and return
                # empty content when the budget runs out before the answer.
                reasoning = (message.get("reasoning_content") or "").strip()
                if reasoning:
                    log(
                        f"  ! no content; {len(reasoning)} chars of reasoning only "
                        f"(max_output_tokens={max_tokens} too low)"
                    )
            return content, finish
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            last = RuntimeError(f"HTTP {exc.code}: {detail}")
            # 4xx other than rate limiting will not fix themselves.
            if exc.code not in (408, 429) and exc.code < 500:
                break
        except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
            last = exc
        backoff = 2**attempt
        log(f"  ! model request failed ({last}); retrying in {backoff}s")
        time.sleep(backoff)
    raise RuntimeError(f"model request failed: {last}")


FENCE_OPEN = re.compile(r"^[ \t]*(`{3,}|~{3,})[ \t]*([A-Za-z0-9_+-]*)[ \t]*$")
DIAGRAM_START = re.compile(
    r"^\s*(flowchart|graph|sequenceDiagram|classDiagram|stateDiagram(?:-v2)?|erDiagram"
    r"|journey|gantt|pie|C4Context|C4Container|mindmap|timeline|block(?:-beta)?)\b"
)


def fenced_blocks(text: str) -> list[tuple[str, str]]:
    """Walk the response and return every (info string, body) fenced block."""
    lines = text.splitlines()
    blocks: list[tuple[str, str]] = []
    i = 0
    while i < len(lines):
        opened = FENCE_OPEN.match(lines[i])
        if not opened:
            i += 1
            continue
        fence, tag = opened.group(1), opened.group(2).lower()
        close = re.compile(rf"^[ \t]*{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$")
        body: list[str] = []
        i += 1
        while i < len(lines) and not close.match(lines[i]):
            body.append(lines[i])
            i += 1
        blocks.append((tag, "\n".join(body).strip()))
        i += 1
    return blocks


THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def strip_think(text: str) -> str:
    """Remove inline reasoning blocks from a model reply."""
    text = THINK_RE.sub("", text)
    # An unterminated <think> means the reply was cut off mid-reasoning.
    head, sep, _ = text.partition("<think>")
    return (head if sep else text).strip()


def extract_mermaid(text: str) -> str:
    """Pull the mermaid body out of a model response."""
    blocks = fenced_blocks(text)
    for tag, body in blocks:
        if tag == "mermaid" and body:
            return body
    for _, body in blocks:
        if DIAGRAM_START.match(body):
            return body
    stripped = text.strip()
    if DIAGRAM_START.match(stripped):
        return stripped
    raise ValueError("no mermaid diagram found in response")


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def mmdc_available() -> bool:
    return shutil.which("mmdc") is not None or shutil.which("npx") is not None


def validate_mermaid(body: str) -> tuple[bool, str]:
    """Render the diagram with mermaid-cli to prove it parses."""
    if shutil.which("mmdc"):
        cmd_prefix = ["mmdc"]
    elif shutil.which("npx"):
        cmd_prefix = ["npx", "--yes", "@mermaid-js/mermaid-cli@11"]
    else:
        return True, "mermaid-cli unavailable; skipped validation"

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "diagram.mmd"
        out = Path(tmp) / "diagram.svg"
        cfg = Path(tmp) / "puppeteer.json"
        src.write_text(body)
        cfg.write_text(json.dumps({"args": ["--no-sandbox", "--disable-gpu"]}))
        try:
            with RENDER_SEM:
                proc = subprocess.run(
                    [*cmd_prefix, "-i", str(src), "-o", str(out), "-p", str(cfg), "-q"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return True, f"mermaid-cli did not run ({exc}); skipped validation"
        rendered = out.is_file() and out.stat().st_size > 0

    if proc.returncode == 0 and rendered:
        return True, ""

    output = proc.stderr + proc.stdout
    # A toolchain that cannot install or launch is not a broken diagram.
    unavailable = (
        "npm error",
        "npm ERR!",
        "ENOTFOUND",
        "EAI_AGAIN",
        "ETIMEDOUT",
        "Cannot find module",
        "could not determine executable",
        "Could not find Chrome",
        "Failed to launch the browser process",
    )
    if any(marker in output for marker in unavailable):
        return True, "mermaid-cli unavailable; skipped validation"

    noise = ("Store is a Store", "Debugger attached")
    err = "\n".join(
        line
        for line in output.splitlines()
        if line.strip() and not any(n in line for n in noise)
    )
    return False, err[:1500] or f"mermaid-cli exited {proc.returncode}"


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def render_block(spec: Spec, digest: str, body: str) -> str:
    return "\n".join(
        [
            BEGIN.format(id=spec.id, digest=digest),
            "<!-- Generated from the sources listed in .github/diagrams.yaml."
            " Do not edit by hand; edit the manifest instructions instead. -->",
            "",
            "```mermaid",
            body,
            "```",
            "",
            END.format(id=spec.id),
        ]
    )


def existing_digest(text: str, spec_id: str) -> str | None:
    match = re.search(BEGIN_RE.format(id=re.escape(spec_id)), text)
    return match.group("digest") if match else None


def render_page(spec: Spec, block: str, blobs: list[tuple[str, str]], root: Path) -> str:
    """Render the diagram page: title, managed block, and links back to the
    sources it was generated from."""
    here = (root / spec.output).parent
    links = ", ".join(
        f"[`{rel}`]({quote(os.path.relpath(root / rel, here))})" for rel, _ in blobs
    )
    return "\n".join(
        [
            f"# {spec.title}",
            "",
            block,
            "",
            "## Sources",
            "",
            f"Generated from {links}.",
            "",
        ]
    )


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def generate(spec: Spec, blobs: list[tuple[str, str]], dropped: list[str],
             endpoint: "Endpoint", attempts: int, validate: bool) -> str:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_prompt(spec, blobs, dropped)},
    ]
    last_err = ""
    for attempt in range(1, attempts + 1):
        log(f"  attempt {attempt}/{attempts}")
        reply, finish = call_model(
            endpoint, messages, spec.max_tokens, spec.reasoning_effort
        )
        if not reply:
            last_err = (
                f"model returned no content (finish_reason={finish or 'unknown'}); "
                f"raise max_output_tokens above {spec.max_tokens}"
            )
            log(f"  ! {last_err}")
            continue
        try:
            body = extract_mermaid(reply)
        except ValueError as exc:
            last_err = str(exc)
            log(f"  ! {last_err}")
            messages += [
                {"role": "assistant", "content": reply[:4000]},
                {
                    "role": "user",
                    "content": "That reply contained no mermaid code block. Reply with "
                    "exactly one ```mermaid block and nothing else.",
                },
            ]
            continue

        if not validate:
            return body
        ok, err = validate_mermaid(body)
        if ok:
            if err:
                log(f"  ~ {err}")
            return body
        last_err = err
        log(f"  ! mermaid failed to parse:\n{err}")
        messages += [
            {"role": "assistant", "content": f"```mermaid\n{body}\n```"},
            {
                "role": "user",
                "content": "mermaid-cli rejected that diagram:\n\n```\n"
                + err
                + "\n```\n\nFix the syntax and reply with the corrected "
                "```mermaid block only. Quote every label containing "
                "punctuation.",
            },
        ]
    raise RuntimeError(f"could not produce a valid diagram after {attempts} attempts: {last_err}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=".github/diagrams.yaml")
    parser.add_argument("--root", default=None, help="repo root (default: git toplevel)")
    parser.add_argument("--only", nargs="*", default=None, metavar="ID")
    parser.add_argument("--check", action="store_true", help="report staleness, write nothing")
    parser.add_argument("--force", action="store_true", help="ignore the stored digest")
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--no-validate", dest="validate", action="store_false")
    parser.add_argument("--jobs", "-j", type=int, default=DEFAULT_JOBS,
                        help=f"diagrams to generate in parallel (default: {DEFAULT_JOBS})")
    args = parser.parse_args()

    if args.root:
        root = Path(args.root).resolve()
    else:
        try:
            root = Path(
                subprocess.run(
                    ["git", "rev-parse", "--show-toplevel"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
            )
        except (subprocess.CalledProcessError, OSError):
            root = Path.cwd()

    manifest = root / args.manifest
    if not manifest.is_file():
        log(f"no manifest at {manifest}")
        return 1

    specs, _ = load_manifest(manifest, root)
    if args.only:
        wanted = set(args.only)
        unknown = wanted - {s.id for s in specs}
        if unknown:
            log(f"unknown diagram id(s): {', '.join(sorted(unknown))}")
            return 1
        specs = [s for s in specs if s.id in wanted]
    if not specs:
        log("manifest declares no diagrams")
        return 0

    endpoint = None
    if not args.check:
        try:
            endpoint = Endpoint.from_env()
        except KeyError as exc:
            log(f"not set in the environment: {exc}")
            return 1

    stale: list[str] = []
    updated: list[str] = []
    failed: list[str] = []
    pending: list[tuple] = []

    # Staleness is local and cheap; do it in manifest order so the log reads
    # top to bottom and the worklist is deterministic.
    for spec in specs:
        log(f"\n=== {spec.id} -> {spec.output}")
        blobs, dropped = collect_sources(spec, root)
        if not blobs:
            log("  ! no sources matched; check the manifest globs")
            failed.append(spec.id)
            continue
        log(f"  {len(blobs)} source file(s), {sum(len(t) for _, t in blobs)} chars"
            + (f", {len(dropped)} dropped for budget" if dropped else ""))

        target = root / spec.output
        current = target.read_text() if target.is_file() else ""
        digest = digest_for(spec, blobs)
        stored = existing_digest(current, spec.id)

        if stored == digest and not args.force:
            log(f"  up to date (digest {digest})")
            continue

        reason = "missing" if stored is None else f"digest {stored} -> {digest}"
        log(f"  stale: {reason}")
        stale.append(spec.id)
        if args.check:
            continue
        pending.append((spec, blobs, dropped, digest, current))

    def build(job: tuple) -> str:
        """Generate one diagram. Returns updated / unchanged / failed."""
        spec, blobs, dropped, digest, current = job
        try:
            body = generate(spec, blobs, dropped, endpoint, args.attempts, args.validate)
        except (RuntimeError, ValueError) as exc:
            log(f"  ! {exc}")
            return "failed"

        new_text = render_page(spec, render_block(spec, digest, body), blobs, root)
        if new_text == current:
            log("  no change after render")
            return "unchanged"

        target = root / spec.output
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(new_text)
        log(f"  wrote {spec.output}")
        return "updated"

    def run(job: tuple) -> tuple:
        """Buffer this diagram's log so parallel output does not interleave."""
        spec = job[0]
        _local.buf = []
        try:
            outcome = build(job)
        except Exception as exc:  # a worker must never take down the pool
            log(f"  ! unexpected error: {exc!r}")
            outcome = "failed"
        finally:
            lines = getattr(_local, "buf", []) or []
            _local.buf = None
            with PRINT_LOCK:
                print("\n".join([f"\n=== {spec.id}", *lines]), file=sys.stderr, flush=True)
        return spec.id, outcome

    if pending:
        workers = max(1, min(args.jobs, len(pending)))
        globals()["RENDER_SEM"] = threading.Semaphore(
            max(1, min(workers, MAX_CONCURRENT_RENDERS))
        )
        log(f"\ngenerating {len(pending)} diagram(s), {workers} at a time")

        outcomes: dict[str, str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for diagram_id, outcome in pool.map(run, pending):
                outcomes[diagram_id] = outcome

        # Report in manifest order regardless of completion order.
        for job in pending:
            outcome = outcomes.get(job[0].id)
            if outcome == "updated":
                updated.append(job[0].id)
            elif outcome == "failed":
                failed.append(job[0].id)

    summary = Path(os.environ.get("GITHUB_STEP_SUMMARY", "")) if os.environ.get(
        "GITHUB_STEP_SUMMARY"
    ) else None
    if summary:
        lines = ["## Diagrams", ""]
        if args.check:
            lines += [f"- stale: `{i}`" for i in stale] or ["All diagrams are up to date."]
        else:
            lines += [f"- updated `{i}`" for i in updated]
            lines += [f"- **failed** `{i}`" for i in failed]
            if not updated and not failed:
                lines.append("All diagrams are up to date.")
        with summary.open("a") as fh:
            fh.write("\n".join(lines) + "\n")

    if failed:
        log(f"\nfailed: {', '.join(failed)}")
        return 1
    if args.check and stale:
        log(f"\nstale: {', '.join(stale)}")
        return 3
    log(f"\nupdated: {', '.join(updated) if updated else 'nothing'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
