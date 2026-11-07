# The 5-Whys Root Cause Template

When debugging multi-layer exceptions, surface symptoms often mask deeper systemic bugs. Use this template to drill down to the fundamental design defect before modifying code.

## 5-Whys Distillation Schema

Copy and fill this block into your agent scratchpad or response:

```text
Problem Statement: [Exact exception and failing assertion message]

Why 1: Why did the exception trigger at runtime?
  Answer: [Immediate trigger, e.g. function received None instead of dict]

Why 2: Why was that value passed into the failing function?
  Answer: [Caller origin, e.g. parser returned None on unexpected status code]

Why 3: Why did the upstream caller produce that unexpected state?
  Answer: [Contract breakdown, e.g. API returned 429 rate limit instead of JSON body]

Why 4: Why was that condition unhandled by the caller?
  Answer: [Missing invariant, e.g. client assumes all non-500 responses parse as JSON]

Why 5: Why did the system lack this invariant protection?
  Answer: [Root cause, e.g. missing HTTP client error classification middleware]

Target Fix Level: Fix at Level 4/5 (Root Cause), not Level 1 (Symptom Masking).
```

## Anti-Pattern Check

- **Symptom Masking (Anti-Pattern):** Wrapping the Level 1 line in `try ... except Exception: pass` or checking `if x is None: return ""`. This leaves the system in an indeterminate state.
- **Root Cause Resolution (Correct):** Adding HTTP status validation and typed exception handling at Level 4/5.
