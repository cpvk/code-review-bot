# Reading List

Resources directly relevant to building this project. Only what I actually used or found useful.

---

## Diff Parsing & GitHub API

- [Unified Diff Format spec (GNU)](https://www.gnu.org/software/diffutils/manual/html_node/Unified-Format.html) — The canonical reference for `@@` hunk headers, context lines, `+`/`-` lines
- [python-unidiff (GitHub)](https://github.com/matiasb/python-unidiff) — Library we use; study `PatchSet`, `PatchedFile`, `Hunk` classes
- [PyGithub docs](https://pygithub.readthedocs.io/en/latest/introduction.html) — Auth, repos, PRs, posting review comments
- [Creating Actions (GitHub Docs)](https://docs.github.com/en/actions/creating-actions) — Docker-based and composite custom actions

## Tree-sitter & AST Analysis

- [py-tree-sitter docs](https://tree-sitter.github.io/py-tree-sitter/) — Python bindings: `Language`, `Parser`, `Tree`, `Node`, `Query`
- [Tree-sitter: Using Parsers](https://tree-sitter.github.io/tree-sitter/using-parsers/) — Parsing, tree traversal, S-expression queries
- [Using tree-sitter with Python (Simon Willison)](https://til.simonwillison.net/python/tree-sitter) — Concise practical snippets
- [Cyclomatic Complexity (Wikipedia)](https://en.wikipedia.org/wiki/Cyclomatic_complexity) — McCabe metric formula (E - N + 2P), threshold of 10

## LLM-Based Code Review (Papers)

- [AI-powered Code Review with LLMs: Early Results (arXiv 2404.18496)](https://arxiv.org/abs/2404.18496) — 4-agent system (smells, bugs, standards, improvements). Mirrors our multi-pass architecture
- [Augmenting LLMs with Static Analysis for Code Quality (arXiv)](https://arxiv.org/html/2506.10330v1) — Hybrid AST + LLM approach, 16% accuracy improvement
- [Fine-tuning vs Prompt Engineering for Code Review (ScienceDirect)](https://www.sciencedirect.com/science/article/pii/S0950584924001289) — Key finding: few-shot prompting works best when data is limited

## How Existing Tools Work

- [How CodeRabbit built its AI code review agent (Google Cloud)](https://cloud.google.com/blog/products/ai-machine-learning/how-coderabbit-built-its-ai-code-review-agent-with-google-cloud-run) — Architecture: sandboxed execution, 40+ linters + LLM
- [Context Engineering for AI Code Reviews (CodeRabbit)](https://www.coderabbit.ai/blog/context-engineering-ai-code-reviews) — Dependency graphs, commit history, cross-repo analysis
- [Pipeline AI vs Agentic AI for Code Reviews (CodeRabbit)](https://www.coderabbit.ai/blog/pipeline-ai-vs-agentic-ai-for-code-reviews-let-the-model-reason-within-reason) — Fixed pipeline vs agentic architecture tradeoffs

## Prompt Engineering for Security Review

- [Prompting LLMs for Security Reviews (CrashOverride)](https://crashoverride.com/blog/prompting-llm-security-reviews) — Persona assignment, context injection, structured output format

---

## Key Takeaways

| Phase | What I Learned |
|-------|---------------|
| 1 | `unidiff` is strict: context lines MUST have space prefix, hunk line counts must be exact |
| 2 | Tree-sitter gives CST not AST. Parse structurally first, then send focused queries to LLM — reduces hallucinations |
| 3 | Multi-pass review (focused prompts per category) beats single "review everything" prompts. AST pre-filter then LLM reasoning eliminates false positives and saves API cost |

*Last updated: Phase 3 completion*
