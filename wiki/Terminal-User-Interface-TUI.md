# Terminal User Interface (TUI) Dashboard

SkillForge includes an interactive terminal dashboard powered by the Rich console library. It provides a visual overview of context token budgets, security posture, and assistant adapters.

---

## Why a Visual Dashboard?

When managing multiple agent skills, plain CLI output can be difficult to parse quickly. The dashboard answers key questions at a glance:

1. **How much context window budget are my skills consuming?**
2. **Are any installed skills failing security checks or leaking credentials?**
3. **Which coding assistants have active adapters configured in this workspace?**
4. **Are my skills structured using progressive disclosure or monolithic blocks?**

---

## Running the Dashboard

### 1. Static Snapshot Mode

Run a single-pass rendering of the dashboard. This is ideal for CI/CD logs, terminal reports, or non-interactive shells:

```bash
skillforge tui --static
```

### 2. Live Watch Mode

Start an interactive live console that refreshes automatically as you edit skills in your workspace:

```bash
skillforge tui --watch
```

Press `Ctrl+C` to exit watch mode.

---

## Dashboard Layout and Metrics

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ SKILLFORGE v0.4.2  :  Universal Agent Skill Manager & Security Sentinel     │
│ Workspace: /path/to/project                          Status: Operational    │
└─────────────────────────────────────────────────────────────────────────────┘
┌─ Context Token Budget ─┐┌─ Security & Integrity ─┐┌─ Ecosystem & Adapters ──┐
│ Window     Budget      ││ Metric          Value  ││ Target      State       │
│ 8K Tools   2,400/8,192 ││ Security Grade      A  ││ Adapters    2 detected  │
│ 32K Prompt 2,400/32,768││ Critical Findings   0  ││ Local Skills 4 active   │
│ 128K Model 2,400/128,00││ Medium Warnings     0  ││ Standard    AAIF 2026   │
└────────────────────────┘└────────────────────────┘└─────────────────────────┘
┌────────────── Active Skills (Progressive Disclosure & Weight) ──────────────┐
│ Skill Name              Tokens   Disclosure Tier   Security   Description   │
│ git-worktree-isolation     320   Progressive        100/100   Ephemeral...  │
│ atomic-rollback-guard      410   Progressive        100/100   Safe file...  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Context Token Budget Panel

Displays token consumption against industry-standard context boundaries:

* **8K Tools Window:** The tight context window typically allocated to tool descriptions in lightweight models.
* **32K Prompt Window:** Standard system prompt budget for medium-tier coding agents.
* **128K Claude Window:** Large context window budget for extended multi-turn sessions.

### Security and Integrity Panel

Provides real-time scoring based on the `SkillAuditor` engine:

* **Security Grade:** Letter grade (A for 90+, B for 80+, C for 70+, F below 70).
* **High and Critical Findings:** Immediate count of blockers requiring review.
* **Sandbox Status:** Verification that offline subprocess and network blocks are operating.

### Active Skills Table

Lists installed skills with their estimated token weights, progressive disclosure status, and security compliance scores.
