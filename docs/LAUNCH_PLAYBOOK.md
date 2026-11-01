# SkillForge Launch & Distribution Playbook

This document outlines the tactical execution plan to maximize star velocity, community adoption, and reach the GitHub Trending page.

---

## 1. Show HN Launch (Hacker News)

Hacker News favors technical authenticity, architectural transparency, and solving real developer friction. Avoid marketing buzzwords ("revolutionary", "all-in-one", "AI-powered"). Emphasize specifications, offline determinism, and problem-solving.

### Target Timing
- **Day:** Tuesday, Wednesday, or Thursday
- **Time:** 8:00 AM – 10:00 AM EST (13:00 – 15:00 UTC)

### Title Format
```text
Show HN: SkillForge – Security auditor, token budget profiler, and package manager for Agent Skills
```

### First Comment Template (Post immediately after submission)
```text
Hi HN, I'm the creator of SkillForge (https://github.com/gintingism/skillforge).

With the rise of the SKILL.md format across Claude Code, Cursor, Gemini/Antigravity, and Copilot, we’re seeing a rapid influx of third-party agent skills. However, loading unvetted skills into an agent's context introduces two significant problems:

1. Supply-Chain & Prompt Injection Risks: Skills combine natural language instructions with executable scripts. Malicious skills can embed indirect prompt injections, reverse shells, or subtle exfiltration vectors (e.g. leaking .env secrets or ~/.ssh keys). Snyk's ToxicSkills research showed this isn't hypothetical.
2. Context Window & Token Bloat: When developers install 15–20 skills, always-loaded startup metadata can consume thousands of tokens on every single turn, degrading reasoning performance and multiplying API costs.

I built SkillForge as an offline, zero-dependency Python tool (and native MCP server) to solve this:
- Security Linter: Scans for hidden Unicode zero-width tags, prompt injection directives, command injections, credential stealing, and phishing links.
- Context Budget Profiler: Quantifies always-loaded startup pointer cost vs. on-demand body cost, enforcing progressive disclosure rules.
- Deterministic Sync: Uses SHA-256 lockfiles (`skillforge.lock`) with Git commit SHA pinning so team agent setups are 100% reproducible.
- Multi-Assistant Routing: Installs skills to the appropriate directories for Claude Code, Cursor, Antigravity, Windsurf, Cline, or Copilot.
- Native MCP Server: Allows coding agents to inspect, audit, and install skills natively via Model Context Protocol.

You can run it in one command without installation via uvx:
$ uvx agent-skillforge doctor

Code is MIT licensed on GitHub: https://github.com/gintingism/skillforge
PyPI: https://pypi.org/project/agent-skillforge/

I’d love feedback on what security heuristics or assistant adapters you'd like to see added next!
```

---

## 2. Reddit Distribution

Submit non-promotional, architecture-focused posts to relevant developer subreddits on the same day as the HN launch:

### Subreddits
1. **r/LocalLLaMA** (Audience: LLM practitioners, safety, open-source AI tooling)
2. **r/Python** (Audience: Python developers looking for uvx/Python alternatives to Node CLIs)
3. **r/ClaudeAI** & **r/CursorAI** (Audience: Power users looking to manage skills cleanly)

### Reddit Post Template
**Title:**
```text
I built SkillForge: An open-source security auditor, token budgeter, and package manager for AI Agent Skills (SKILL.md)
```

**Body:**
Highlight the contrast between running unvetted markdown instructions and running an offline auditor with progressive disclosure checks. Include code blocks and terminal outputs.

---

## 3. Twitter / X Announcement Thread

**Tweet 1 (The Hook + Demo GIF):**
```text
Agent Skills (SKILL.md) are becoming the universal way to extend Claude Code, Cursor, & Gemini.

But third-party skills can easily smuggle prompt injections, steal .env tokens, or burn your context window.

Introducing SkillForge: The open-source security auditor & package manager for Agent Skills. 🧵👇
[Attach assets/demo.gif]
```

**Tweet 2 (Security):**
```text
1/ Security Linter (Offline & Deterministic)
SkillForge scans skill packages for:
- Invisible zero-width unicode characters
- Prompt injections & safety bypasses
- Dangerous shell execution (curl | bash)
- Credential exfiltration & API key leaks

$ uvx agent-skillforge audit ./skills/my-skill
```

**Tweet 3 (Context Budget):**
```text
2/ Context Window Budgeting
Every skill you install adds startup overhead. SkillForge profiles your always-loaded pointer tokens vs on-demand body tokens to prevent context bloat and lower your API bills.

$ uvx agent-skillforge budget
```

**Tweet 4 (Cross-Assistant + MCP):**
```text
3/ Write Once, Run Everywhere
SkillForge detects your assistant and routes skills to Claude Code, Cursor, Antigravity, Windsurf, or Copilot.

It even exposes a native MCP server (`skillforge serve-mcp`) so agents can audit and manage skills autonomously.
```

**Tweet 5 (Links & CTA):**
```text
Zero-install quickstart:
$ uvx agent-skillforge doctor

⭐ Star on GitHub: https://github.com/gintingism/skillforge
📦 PyPI: https://pypi.org/project/agent-skillforge/
```

---

## 4. Viral Growth Loops & Community PRs

1. **Submit to Curated Lists:**
   - Open a PR to add SkillForge to `awesome-agent-skills` (VoltAgent), `awesome-claude-skills`, and `modelcontextprotocol/servers`.
2. **"Audited by SkillForge" Badge:**
   - Encourage skill creators to run `skillforge badge <skill>` and embed the verified shield badge into their `SKILL.md` or `README.md`. Every badge links back to the SkillForge repository.
3. **GitHub Action Integration:**
   - Promote `uses: gintingism/skillforge@v0.4.1` as the standard pre-merge security check for teams creating agent skills.
