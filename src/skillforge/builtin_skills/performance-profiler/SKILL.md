---
name: performance-profiler
description: Isolate latency bottlenecks, N+1 query patterns, memory allocations, and algorithmic complexity regressions using baseline-first measurement. Use when optimizing slow endpoints, high CPU/memory usage, or database queries.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Performance Profiler Protocol

Never optimize by intuition. Measure baseline latency, query count, or allocation volume before modifying code, and prove the delta with a repeatable benchmark.

## 1. Capture the Baseline

1. **Reproduce with Realistic Cardinality**:
   - Run the target path against representative dataset sizes ($N \ge 10^3$ rows or items) rather than trivial unit-test fixtures ($N = 2$).
2. **Record Primary Metrics**:
   - Capture wall-clock latency (`p50`, `p95`, `p99`), total SQL/RPC round-trips per request, or peak heap allocation before touching implementation code.

## 2. Isolate the Dominant Bottleneck

- **I/O & Query Amplification (N+1)**:
  - Check whether loop bodies issue sequential queries, network calls, or filesystem reads. Batch into a single `WHERE id IN (...)` query, join, or bulk RPC.
- **Algorithmic Complexity ($O(N^2)$ Traps)**:
  - Replace repeated linear scans (`item in list`, nested filter loops, repeated string/array concatenation) with hash sets, indexed maps, or single-pass accumulators.
- **Serialization & Payload Bloat**:
  - Project only required columns (`SELECT id, status` instead of `SELECT *`), stream large responses, and avoid re-parsing static configurations inside hot loops.
- **Unbounded Concurrency or Lock Contention**:
  - Bound parallel fan-out with semaphores and keep network/disk I/O outside database transactions or mutex locks.

## 3. Verification Gate

- Re-run the exact baseline harness after the change and report `before -> after` metrics (latency, query count, or memory) alongside passing functional tests.
