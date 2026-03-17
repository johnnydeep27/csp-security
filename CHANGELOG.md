# Changelog

## 1.2.1 - 2026-03-17

### Bug Fixes

- **Fixed `report-uri` not appearing in CSP header** — Config key was referenced with `cspsecurity.` prefix but stored without it; also removed `FILTER_SANITIZE_URL` that was mangling path-based values
- **Added `form-action` directive to all pages** — Previously only defined when Stripe was enabled; `form-action` does not fall back to `default-src`, so its absence left forms unrestricted (OWASP ZAP: "CSP: Failure to Define Directive with No Fallback")
- **Added `frame-src` directive to all pages** — Same no-fallback issue; now defaults to `'self'` plus custom domains, upgraded with Stripe domains when Stripe is active
- Simplified `report-uri` validation to accept full URLs and absolute paths without intermediate sanitisation
- Invalid `report-uri` values are now always logged (not only in debug mode)

## 1.2.0 - 2026-02-16

### Security

- **Nonce generation hardened** — Removed `mt_rand()` and `microtime()` from `generateSecureNonce()`; now uses only `bin2hex(random_bytes(16))` for cryptographically secure output
- **Removed automatic `'unsafe-eval'` and `'unsafe-inline'` for Stripe** — Modern Stripe.js (v3+) works with nonces alone; these are no longer forced into the CSP when Stripe is detected
- **`style-src` no longer uses `'unsafe-inline'` by default** — Uses nonces and SHA-256 hashes instead; opt back in with the new `allow_unsafe_inline_styles` setting

### New Features

- New System Settings
    - `allow_unsafe_eval` — Explicitly opt in to `'unsafe-eval'` in `script-src` when required
    - `allow_unsafe_inline_styles` — Explicitly opt in to `'unsafe-inline'` in `style-src` when required
    - `object_src` — Set `object-src` directive value (`'none'` or `'self'`); defaults to `'none'`
    - `custom_style_hashes` — Comma-separated SHA-256/384/512 hashes to add to `style-src` (paste values from browser console)
    - `custom_script_hashes` — Comma-separated SHA-256/384/512 hashes to add to `script-src`
- **Font domain detection** — New `$commonFontDomains` list and `getFontDomains()` method; `font-src` now uses specific detected domains instead of a blanket `https:`
- **Centralised domain collection** — New `getAllAllowedDomains()` method; custom domains now propagate to `default-src`, `img-src`, `connect-src`, `frame-src`, and `form-action`
- **Wildcard subdomain support** — `isValidDomain()` now accepts `*.example.com` patterns in `custom_domains`
- **`child-src` directive** — Added for older-browser Stripe iframe compatibility

### Improvements

- **Inline event pattern expanded** — Now also hashes `oninvalid` and `oninput` handlers
- **`base-uri` tightened** — Removed `data:` and external sources; now `'self'` only
- **CSP header length validation** — Logs a warning when the header exceeds 8 192 characters
- **Double-space cleanup** — All CSP directive parts are trimmed before joining
- **Error handling improved** — `process()` catches both `Exception` and `Error`; `setCSPHeader()` wrapped in try/catch to prevent 502 errors
- **Debug logging enhanced** — Logs loaded custom domains on startup and CSP header length on each request
- **Style attribute hashing re-enabled** — Inline `style="…"` attributes are now SHA-256 hashed with `'unsafe-hashes'` in `style-src`, allowing them without `'unsafe-inline'`

## 1.1.0 - 2025-05-25

### New Features

- Automatic Stripe Detection
    - Detects Stripe usage on pages by scanning for Stripe scripts, API calls, and elements
    - Only applies Stripe-specific CSP rules when Stripe is actually being used
- New Configuration Options
    - enable_stripe
    - stripe_environment
    - allow_stripe_forms
    - allow_stripe_webhooks
- Stripe Domain Whitelist
    - Automatically includes all necessary Stripe domains
- Smart CSP Adjustments
    - Adds 'unsafe-eval' for dynamic script execution
    - Includes frame-src for Stripe Checkout iframes
    - Adds form-action for payment form submissions
    - Temporarily disables 'strict-dynamic' to prevent conflicts
    - Allows 'unsafe-inline' as fallback when needed
- Enhanced Processing
    - Special handling for Stripe elements and forms
    - Preserves existing Stripe script nonces
    - Adds debug logging for Stripe detection

## 1.0.0 - 2025-05-25

### Features

- Automatically adding CSP Headers using OnWebPagePrerender event
- System Settings
    - debug_mode
    - custom_domains
    - enabled
    - report_uri
    - strict_dynamic
    - unsafe_hashes
    - override_existing_nonces