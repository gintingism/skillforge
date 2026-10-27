---
name: summarize
description: Distill complex engineering documents, logs, and pull request diffs into structured executive summaries with citations and key architectural decisions. Use when summarizing technical repositories or code reviews.
license: MIT
compatibility: Universal
metadata:
  version: "1.1.0"
  author: "SkillForge Team"
---

# Technical Summarization Protocol

Distill dense technical transcripts, diffs, and architectural documents into high-signal summaries.

## Rules

1. **Context & Objective**: State the core objective and background in 1-2 sentences.
2. **Key Architectural Decisions**: Bullet points of decisions made, rationale, and alternatives rejected.
3. **Exact Citations**: Link to specific files, functions, and line numbers (`path/to/file.py#L12-L30`).
4. **Actionable Next Steps**: Bulleted list of open questions, blocker items, or follow-up tasks.
