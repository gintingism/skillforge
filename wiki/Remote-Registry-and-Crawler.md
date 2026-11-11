# Remote Registry and Repository Indexer

This document details how SkillForge discovers, indexes, and safely installs community agent skills from public and private repositories.

---

## The Remote Discovery Problem

With the adoption of open skill standards under the Linux Foundation Agentic AI Foundation (AAIF) and platforms like SkillsMD, thousands of agent skills are published across GitHub and community hubs.

However, installing unvetted skills directly into local coding assistants introduces major supply chain risks. SkillForge solves this by pairing remote discovery with an automatic security verification gate.

---

## Searching Remote Skills

Search the curated remote index of verified skills by keyword or tag:

```bash
# Search for skills matching a query
skillforge search-remote "security"

# Filter skills by a specific tag
skillforge search-remote "" --tag git

# Search by topic
skillforge search-remote "trifecta"
```

Sample output:
```text
Found 1 remote skill(s):
  lethal-trifecta-guard            gintingism/skillforge:lethal-trifecta-guard      [VERIFIED]
    Detects lethal trifecta: credential access + untrusted ingestion + outbound egress.
```

---

## Indexing Repositories

You can crawl any local directory or cloned Git repository to extract `SKILL.md` packages, calculate security scores, and register them into your local discovery catalog:

```bash
# Scan and index a repository directory
skillforge index ./community-skills --url https://github.com/my-org/skills
```

SkillForge walks the folder, parses every skill package, runs the full `SkillAuditor` engine, and records the results into `~/.skillforge/remote_index.json`:

```text
Indexed 3 skill(s) from community-skills into ~/.skillforge/remote_index.json.
  + database-guard (my-org/skills:database-guard) - Security Score: 100/100
  + docker-helper (my-org/skills:docker-helper) - Security Score: 95/100
  + k8s-debugger (my-org/skills:k8s-debugger) - Security Score: 100/100
```

---

## Automatic Installation Security Gate

When you install a skill using `skillforge install` or `skillforge add`, SkillForge automatically runs a security audit on the package before copying files into your assistant directories (`.claude/skills`, `.cursor/skills`, `.gemini/config/skills`).

### Default Policy Enforcement

* **Minimum Score:** 80 out of 100 points.
* **Strict Blocker:** Zero CRITICAL or HIGH severity findings.

If a package violates these criteria, the installation is rejected immediately:

```bash
skillforge install insecure-community-skill
```

Output:
```text
Security audit gate rejected installation for 'insecure-community-skill' (Score: 40/80)
  [CRITICAL] SEC-002: Prompt injection pattern detected
  [HIGH] SEC-004: Direct access to local credentials (~/.ssh)
Use --insecure to bypass this security gate if you trust the source.
```

The process terminates with exit code 2 to prevent malicious files from touching your filesystem.

### Explicit Bypass (`--insecure`)

For security researchers or local testing of known experimental packages, you can explicitly bypass the audit gate:

```bash
skillforge install insecure-community-skill --insecure
```
