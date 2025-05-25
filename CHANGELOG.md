# Changelog

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