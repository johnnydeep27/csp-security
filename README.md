# CSP Security for MODX

A CSP header generator that automatically generates secure nonces on `<style>` and `<script>` tags via the `OnWebPagePrerender` event, producing a fresh nonce on every page load.

## Features
- Cryptographically secure nonces (`random_bytes`) — no `mt_rand()` or `microtime()`
- Option to override existing nonces
- `report-uri` accepts full URL, absolute path, relative path, or path with query
- Add custom domains (comma-separated), including wildcard subdomains (`*.example.com`)
- Automatic detection of common CDN and font domains
- SHA-256 hashing for inline event handlers (`onclick`, `onload`, `oninvalid`, `oninput`, etc.)
- SHA-256 hashing for inline `style="…"` attributes with `'unsafe-hashes'` — no `'unsafe-inline'` needed
- `style-src` secured with nonces by default (opt-in `'unsafe-inline'` via setting)
- `font-src` scoped to detected font domains instead of blanket `https:`
- CSP header length validation with warning logging
- Robust error handling to prevent 502 errors

## Stripe Payment Compatibility (v1.1.0+)
- Automatic Stripe Detection
    - Detects Stripe usage on pages by scanning for Stripe scripts, API calls, and elements
    - Only applies Stripe-specific CSP rules when Stripe is actually being used
- Configuration Options
    - `enable_stripe` — Enable Stripe CSP support
    - `stripe_environment` — `live` or `test`
    - `allow_stripe_forms` — Allow form-action to Stripe Checkout
    - `allow_stripe_webhooks` — Allow webhook endpoints
- Stripe Domain Whitelist
    - Automatically includes all necessary Stripe domains (`js.stripe.com`, `checkout.stripe.com`, etc.)
- Smart CSP Adjustments
    - Includes `frame-src` and `child-src` for Stripe Checkout iframes
    - Adds `form-action` for payment form submissions
    - Temporarily disables `strict-dynamic` when Stripe is present to prevent conflicts
    - Preserves existing Stripe script nonces
    - No longer forces `'unsafe-eval'` or `'unsafe-inline'` — modern Stripe.js v3+ works with nonces

## System Settings

| Setting | Default | Description |
|---|---|---|
| `cspsecurity.enabled` | `true` | Enable/disable the plugin |
| `cspsecurity.debug_mode` | `false` | Log CSP headers and detection details |
| `cspsecurity.custom_domains` | ` ` | Comma-separated allowed domains (supports `*.example.com`) |
| `cspsecurity.strict_dynamic` | `true` | Add `'strict-dynamic'` to `script-src` |
| `cspsecurity.unsafe_hashes` | `true` | Wrap inline-event hashes with `'unsafe-hashes'` |
| `cspsecurity.override_existing_nonces` | `true` | Replace pre-existing nonces with generated ones |
| `cspsecurity.report_uri` | ` ` | CSP violation report endpoint URL |
| `cspsecurity.allow_unsafe_eval` | `false` | Add `'unsafe-eval'` to `script-src` |
| `cspsecurity.allow_unsafe_inline_styles` | `false` | Use `'unsafe-inline'` instead of nonces for `style-src` |
| `cspsecurity.object_src` | `none` | Set `object-src` directive value (`none` or `self`) |
| `cspsecurity.custom_style_hashes` | | Comma-separated hashes for `style-src` (e.g. `sha256-abc123,sha256-xyz789`) |
| `cspsecurity.custom_script_hashes` | | Comma-separated hashes for `script-src` (e.g. `sha256-abc123`) |
| `cspsecurity.enable_stripe` | `false` | Enable Stripe-specific CSP rules |
| `cspsecurity.stripe_environment` | `live` | Stripe environment (`live` / `test`) |
| `cspsecurity.allow_stripe_forms` | `true` | Allow `form-action` to Stripe Checkout |
| `cspsecurity.allow_stripe_webhooks` | `false` | Allow Stripe webhook endpoints |

## How to Use
1. Install the plugin and set the system settings in MODX.
2. For Stripe support, enable:
    ```
    cspsecurity.enable_stripe = 1
    cspsecurity.allow_stripe_forms = 1
    ```
3. The plugin will automatically:
    - Add nonces to all `<script>` and `<style>` tags
    - Detect when Stripe is used on a page
    - Apply appropriate CSP headers
4. For debugging, enable:
    ```
    cspsecurity.debug_mode = 1
    ```

## License
CSP Security is released under the MIT License. See the LICENSE file for details.

## Author
johnnydeep27