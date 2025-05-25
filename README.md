# CSP Security for MODX

A CSP header generator that automatically generates secure nonce on style, and script tags on OnWebPagePrerender event and dynamically generates new nonce everytime the website reloads 

## Features
- Option to override custom nonces
- report-uri accepts full URL, absolute path, relative path, path with query
- Add custom domains

## New Features on version 1.1.0
- Stripe Payment Compatibility 
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

## How to Use:
1. Set the system settings in MODX:
    `cspsecurity.enable_stripe = 1`
    `cspsecurity.allow_stripe_forms = 1`
2. The plugin will automatically:
    - Detect when Stripe is used on a page
    - Apply appropriate CSP headers
    - Allow all necessary Stripe functionality
3. For debugging, enable:
    `cspsecurity.debug_mode = 1`

## License
CSP Security is released under the MIT License. See the LICENSE file for details.

## Author
johnnydeep27