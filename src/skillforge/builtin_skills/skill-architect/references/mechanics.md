# Skill Invocation & Context Budget Mechanics

## Startup Discovery Budget

Agent harnesses inject a compact catalog of all model-invoked skills at session startup.

| Metric | Recommended Limit | Hard Ceiling |
|--------|-------------------|--------------|
| `description` length | <= 220 characters | 1024 characters |
| Startup pointer cost per skill | 25–60 tokens | 100 tokens |
| `SKILL.md` body length | <= 300 lines | 500 lines / 5,000 tokens |

## Model-Invoked vs. User-Invoked Skills

1. **Model-Invoked (Default)**:
   - `disable-model-invocation` is omitted or `false`.
   - Must include trigger keywords (`Use when`, `When`, `For`) in `description` so the model routes matching tasks accurately (`QUAL-001`).
2. **User-Invoked (`disable-model-invocation: true`)**:
   - Triggered explicitly by the user via `/skill-name`.
   - Consumes **0 startup pointer tokens**.
   - Do not include model trigger clauses in `description`; summarize only what the command executes for human readers.

## Verification Checklist

1. Run `skillforge validate <skill-dir>` to verify schema compliance.
2. Run `skillforge audit <skill-dir> --strict` to verify zero prompt-injection patterns, intact `references/` and `scripts/` pointers (`QUAL-004`), and body budget compliance (`QUAL-003`).
3. Run `skillforge budget -p <project>` to inspect total startup pointer tokens across all installed skills.
