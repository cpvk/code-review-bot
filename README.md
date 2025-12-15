# AI Code Reviewer

AI-powered GitHub code review bot: tree-sitter AST analysis first, then
focused multi-pass LLM reasoning (security, bugs, performance, style).
The AST pre-filter surfaces deterministic signals, suppresses noise, and
only spends LLM calls where there is something worth reasoning about.

## Architecture at a glance

```
PR diff ──> diff_parser ──> context_gatherer ──> ast_analyzer (tree-sitter)
                                                        │
                              ┌─────────────────────────┼──────────────────┐
                              ▼                         ▼                  ▼
                       SecurityReviewer          BugReviewer      Performance / Style
                              └──────────── dedup + confidence filter ────┘
                                                        │
                                               comment_formatter ──> GitHub review
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the in-depth design and
[Readlist.md](Readlist.md) for the papers and references behind it.

## Quickstart (local)

Requires Python 3.13.11 (`>=3.11,<3.14` supported).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest            # 113+ tests, no network or API keys needed
```

AST-only mode needs no LLM key: leave `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`
unset and the reviewers fall back to deterministic AST findings.

## Run on a pull request

Set the variables from [.env.example](.env.example), then:

```bash
GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo PR_NUMBER=42 \
ANTHROPIC_API_KEY=... python -m src.main
```

## Use as a GitHub Action

```yaml
- uses: ./            # or the published action once released
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    review_passes: security,bug,performance,style
    confidence_threshold: "0.5"
```

Inputs are defined in [action.yml](action.yml); the self-review workflow
in [.github/workflows/code-review.yml](.github/workflows/code-review.yml)
is a working example.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `LLM_PROVIDER` | `anthropic` | `anthropic` or `openai` |
| `REVIEW_PASSES` | `security,bug,performance,style` | Enabled passes |
| `MAX_FILES` | `20` | Max Python files reviewed per PR |
| `CONFIDENCE_THRESHOLD` | `0.5` | Min confidence to post a comment |

Typed, validated configuration lives in `src/config.py`; the canonical
finding schema lives in `src/models.py`.

## Project layout

| Path | Role |
|---|---|
| `src/diff_parser.py` | Unified-diff / GitHub files → structured `PRDiff` |
| `src/ast_analyzer.py` | Tree-sitter CST → complexity, calls, security signals |
| `src/context_gatherer.py` | Full file, imports, signatures, tests, history |
| `src/reviewers/` | One focused pass per category (AST pre-filter → LLM) |
| `src/llm_engine.py` | Anthropic / OpenAI providers, structured JSON parsing |
| `src/github_client.py` | PR fetch + review posting (PyGithub) |
| `src/main.py` | Pipeline orchestration |
| `dashboard/app.py` | Streamlit viewer for saved review JSON |
| `tests/` | Unit tests with vulnerable/clean fixtures |

## Tooling

Dependencies, the Docker base image, and CI use the versions pinned in
`requirements.txt` and `pyproject.toml` for reproducible installs.
Upgrade one package at a time and run the test suite after each bump.

## Status

Phases 1–3 are implemented: diff parsing, AST analysis, context gathering,
and the four LLM review passes. The roadmap (multi-language analysis,
evaluation harness, incremental reviews, suppression memory) is in
[ARCHITECTURE.md](ARCHITECTURE.md#roadmap).
