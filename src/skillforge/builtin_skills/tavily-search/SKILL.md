---
name: tavily-search
description: Execute targeted web research across high-trust primary sources, official documentation, and technical repositories. Use when researching cutting-edge library APIs, SDKs, or current industry standards.
license: MIT
compatibility: Python 3.10+
metadata:
  version: "1.1.0"
  author: "SkillForge Team"
---

# Targeted Technical Web Search

Conduct high-signal research across authoritative primary sources (GitHub, official docs, RFCs) while filtering out low-quality SEO scrapers.

## Guidelines

1. **Query Construction**:
   - Use exact symbols, method names, and package specifiers.
   - Target official domains where possible (`site:docs.python.org`, `site:github.com`).
2. **Triangulation**:
   - Cross-reference claims across at least two independent primary sources before advising the user.
3. **Citation Quality**:
   - Always cite exact URLs and timestamp context when reporting findings.
