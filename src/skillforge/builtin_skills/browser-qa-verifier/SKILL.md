---
name: browser-qa-verifier
description: Verify frontend UI and web application flows in a live headless browser using Playwright or DevTools. Use when testing rendered web pages, inspecting browser console errors, auditing network requests, or checking responsive layouts.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Live Browser QA & Verification Protocol

A frontend change is not complete when the bundler compiles. Verify the rendered DOM, interactive controls, console log cleanliness, and network responses in a real headless browser.

## Phase 1: Dev Server & Route Readiness
1. Detect active dev server ports or start the application server locally.
2. Confirm the target route responds with HTTP 200 before launching browser checks.

## Phase 2: Runtime Console & Network Audit
1. Attach listeners to capture `console.error`, uncaught page exceptions, and failed network requests (HTTP 4xx/5xx or CORS rejections).
2. Navigate to the target URL and wait for network idle and initial hydration.
3. Fail verification immediately if any unhandled runtime exception or broken asset request occurs.

## Phase 3: Interactive & State Coverage
1. Exercise every modified interactive control (buttons, forms, modals, tabs, dropdowns) using accessible locators (`getByRole`, `getByLabel`).
2. Verify all three data states where applicable:
   - **Empty state** when zero records exist.
   - **Loading state** while requests are in flight.
   - **Error state** when upstream requests fail.
3. Check mobile (`375x812`) and desktop (`1440x900`) viewports for horizontal overflow and clipped controls.
4. Consult `references/playwright-checklist.md` for locator priority rules and assertion patterns.
