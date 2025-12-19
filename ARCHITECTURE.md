# Architecture

In-depth design of the AI Code Reviewer. For the quickstart see
[README.md](README.md); for sources see [Readlist.md](Readlist.md).

## Design principle: static analysis first, LLM second

A single "review everything" prompt hallucinates, costs more, and cannot
be tested deterministically. This system inverts that:

1. **Deterministic signals first.** Tree-sitter parses each changed Python
   file into a concrete syntax tree. `src/ast_analyzer.py` extracts
   function boundaries, parameters and return types, cyclomatic complexity
   (McCabe), nesting and loop counts, external/DB/file/network calls,
   error-handling shape, variable mutations, and security-sensitive calls
   (`eval`, `subprocess`, `pickle.loads`, f-strings in queries, …).
2. **Focused LLM reasoning second.** Each review pass receives only the
   signals relevant to its category plus the code, and must validate or
   refute them. Passes with no signals skip the LLM call entirely
   (security, performance), which cuts cost and false positives.
3. **Typed boundaries.** Raw LLM JSON is validated through the `Finding`
   schema in `src/models.py`; malformed entries are dropped, never posted.
   Configuration is validated the same way in `src/config.py`.

## Pipeline (`src/main.py`)

| Stage | Module | Output |
|---|---|---|
| Fetch PR | `github_client.GitHubClient` | metadata, file list with patches |
| Parse diff | `diff_parser.parse_github_pr_files` | `PRDiff` → files, hunks, added line numbers |
| Gather context | `context_gatherer.gather_context` | full source, imports, imported-module signatures, related tests, recent commits |
| Analyse | `ast_analyzer.analyze_python_file` | `FileAnalysis` per file |
| Review ×4 | `reviewers/*` | finding dicts (AST, LLM, or merged) |
| Dedup + filter | `dedup.deduplicate_findings`, confidence threshold | highest-confidence finding per (file, line, category) |
| Post | `github_client.post_review` | one GitHub review; falls back to per-line comments |

Findings are only posted on lines present in the diff; off-diff findings
snap to the nearest added line. With no LLM key configured the pipeline
runs AST-only (`_NoOpLLM` in `main`) and still posts deterministic
findings — useful for CI gates and offline testing.

## Review passes

Each pass follows AST pre-filter → focused prompt → structured LLM call →
merge (shared `src/dedup.merge_findings`; LLM wins ties, tagged
`source="llm"`).

| Pass | AST pre-filter signals | Prompt focus |
|---|---|---|
| `SecurityReviewer` | dangerous calls, hardcoded-secret globals, `shell=True`, string formatting in queries | injection, deserialization, path traversal, secrets, SSRF |
| `BugReviewer` | bare `except`, I/O without error handling, high complexity + nesting | None dereference, off-by-one, resource leaks, races |
| `PerformanceReviewer` | nested loops, DB/network calls inside loops, complexity ≥ 15 | N+1, blocking in async, repeated computation |
| `StyleReviewer` | >5 params, complexity > 10, >50-line functions, missing return type | naming, duplication, SOLID, magic values |

Prompts live in `prompts/*.txt` and are loaded at runtime, so tuning a
pass never requires a code change.

## Key decisions and trade-offs

- **Tree-sitter CST over Python `ast`.** Tree-sitter tolerates partial or
  syntactically broken files mid-edit and gives byte-accurate node ranges;
  the analyser walks block structure without double-counting calls.
- **Dict compatibility at the edges, models at the boundaries.** Reviewers
  keep their tested dict interface; `models.validate_findings` and
  `config.ReviewConfig` validate everything entering or leaving the
  pipeline.
- **One canonical formatter.** `comment_formatter.format_review_comment`
  renders every posted comment; `github_client` delegates to it.
- **Context is budgeted by construction.** Prompts carry focused AST
  summaries (not whole-repo dumps), capped test excerpts, and imported
  signatures — the context-engineering pattern that keeps reviews accurate
  without blowing the token budget.

## Testing

`tests/` (120+ cases, no network or API keys) covers diff parsing edge
cases (renames, exact hunk line counts), AST metrics against vulnerable
and clean fixtures (`tests/fixtures/`), every reviewer's pre-filter and
merge, context resolution, and the typed models/config/dedup layer.
Run: `python -m pytest`.

## Roadmap

1. **More languages** — tree-sitter grammars for TypeScript and Go behind
   the same `FileAnalysis` contract.
2. **Evaluation harness** — labelled PR corpus scoring precision/recall
   per pass before prompt or model changes ship.
3. **Incremental reviews** — re-review only changed hunks on
   `synchronize`, resolving threads for findings that disappeared.
4. **Suppression memory** — remember dismissed findings per repo so the
   same false positive is never posted twice.
5. **Webhook service** — long-lived deployment alongside the current
   GitHub Action (Docker) mode.
