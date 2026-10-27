---
name: spec-driven-development
description: Design systems contract-first using typed schemas, OpenAPI/JSON-Schema models, and failing test harnesses before writing application logic. Use when architecting new modules, APIs, or data models.
license: MIT
compatibility: Universal
metadata:
  version: "1.1.0"
  author: "SkillForge Team"
---

# Spec-Driven Development

Define contracts, interfaces, and boundary constraints before writing implementation code. Ensure every feature is grounded in an explicit specification.

## Workflow

1. **Contract Definition**:
   - Write typed schema definitions (Pydantic models, TypeScript interfaces, or JSON Schema).
   - Document preconditions, invariants, and edge cases (nullability, bounds, error types).
2. **Red-Green Test Harness**:
   - Write failing automated tests asserting contract compliance.
   - Run tests to confirm failures occur for the expected reason.
3. **Surgical Implementation**:
   - Write the minimum viable code to fulfill the contract.
   - Refactor while keeping the contract suite green.
