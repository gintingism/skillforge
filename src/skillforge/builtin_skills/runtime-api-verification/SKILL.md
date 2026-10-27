---
name: runtime-api-verification
description: Introspect installed packages, verify method signatures, and inspect type definitions before invoking unfamiliar third-party library APIs. Use when integrating third-party SDKs, upgrading dependencies, or resolving import errors.
license: MIT
compatibility: Python, Node.js / TypeScript, Go
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Runtime API Verification Protocol

Language models frequently hallucinate non-existent kwargs, deprecated class names, or obsolete method signatures due to training-data version drift (e.g., Pydantic v1 vs v2, LangChain transitions, SDK overhauls). Follow this introspection protocol before writing speculative code.

## 1. Inspect Exact Runtime Version
Never assume package version matches latest online documentation:
```bash
# Python
python -c "import <pkg>; print(getattr(<pkg>, '__version__', 'unknown'))"
# Node.js
node -e "console.log(require('<pkg>/package.json').version)"
```

## 2. Introspect Signatures via Interpreter
Before calling a method with complex kwargs, query the runtime's actual signature:
```python
# Verify callable existence and argument names
python -c "
import inspect, <pkg>
target = getattr(<pkg>, '<symbol>')
print('Callable:', callable(target))
print('Signature:', inspect.signature(target))
"
```

## 3. Verify TypeScript / Type Definitions
In TypeScript/JavaScript projects:
1. Check the local `node_modules/<pkg>/index.d.ts` or exported type declaration.
2. Verify exported types via `tsc --noEmit` on a 2-line test file rather than guessing interfaces.

## 4. The 3-Line Probe Script
When integrating an external API client or database driver:
1. Write a minimal, throwaway probe script in `<workspace>/scratch/probe.py` or `.ts`.
2. Execute it once: verify actual return types, error formats, and network expectations.
3. Only after the probe runs cleanly, integrate the logic into the production codebase.
