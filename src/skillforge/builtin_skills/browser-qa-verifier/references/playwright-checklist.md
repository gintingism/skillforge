# Playwright & Headless Browser Verification Checklist

## 1. Locator Priority Order
Always select elements using user-visible semantics rather than brittle CSS classes:
1. `page.get_by_role("button", name="Submit")`
2. `page.get_by_label("Email address")`
3. `page.get_by_placeholder("Search...")`
4. `page.get_by_text("No results found")`
5. `page.get_by_test_id("checkout-total")` (fallback when semantic roles do not apply)

## 2. Mandatory Runtime Listeners
Capture silent runtime failures during every browser verification pass:

```python
console_errors: list[str] = []
failed_requests: list[str] = []

page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
page.on("pageerror", lambda err: console_errors.append(str(err)))
page.on("response", lambda res: failed_requests.append(f"{res.status} {res.url}") if res.status >= 400 else None)
```

## 3. Keyboard & Focus Checks
- Press `Tab` across primary controls and verify `document.activeElement` advances in visual order.
- Open dialogs and verify pressing `Escape` closes the modal and restores focus.
