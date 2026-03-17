<?php
/**
 * CSP Security Plugin for MODX - Stripe Compatible
 * 
 * Copyright (c) 2025 johnnydeep27
 * 
 * @license MIT
 * @package cspsecurity
 * 
 * Events: OnWebPagePrerender
 * 
 * This plugin adds Content Security Policy (CSP) headers with nonces
 * to enhance website security by preventing XSS attacks.
 * Now includes Stripe payment compatibility.
 */

use MODX\Revolution\modX;

class CSPSecurityHandler
{
    /** @var modX $modx */
    private $modx;
    
    /** @var array $config */
    private $config;
    
    /** @var array $nonces */
    private $nonces = [];
    
    /** @var array $allowedDomains */
    private $allowedDomains = [];

    /** @var array $stripeDomains */
    private $stripeDomains = [
        'https://js.stripe.com',
        'https://checkout.stripe.com',
        'https://api.stripe.com',
        'https://connect.stripe.com',
        'https://m.stripe.com',
        'https://dashboard.stripe.com',
        'https://hooks.stripe.com',
        'https://files.stripe.com'
    ];

    /** @var array $commonFontDomains */
    private $commonFontDomains = [
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com',
        'https://maxcdn.bootstrapcdn.com',
        'https://stackpath.bootstrapcdn.com',
        'https://unpkg.com'
    ];

    public function __construct(modX &$modx)
    {
        $this->modx =& $modx;
        $this->loadConfig();
    }

    /**
     * Load configuration from system settings
     */
    private function loadConfig()
    {
        $this->config = [
            'enabled' => (bool) $this->modx->getOption('cspsecurity.enabled', null, true),
            'strict_dynamic' => (bool) $this->modx->getOption('cspsecurity.strict_dynamic', null, true),
            'unsafe_hashes' => (bool) $this->modx->getOption('cspsecurity.unsafe_hashes', null, true),
            'report_uri' => $this->modx->getOption('cspsecurity.report_uri', null, ''),
            'custom_domains' => $this->modx->getOption('cspsecurity.custom_domains', null, ''),
            'debug_mode' => (bool) $this->modx->getOption('cspsecurity.debug_mode', null, false),
            'override_existing_nonces' => (bool) $this->modx->getOption('cspsecurity.override_existing_nonces', null, true),
            'enable_stripe' => (bool) $this->modx->getOption('cspsecurity.enable_stripe', null, false),
            'stripe_environment' => $this->modx->getOption('cspsecurity.stripe_environment', null, 'live'), // 'live' or 'test'
            'allow_stripe_forms' => (bool) $this->modx->getOption('cspsecurity.allow_stripe_forms', null, true),
            'allow_stripe_webhooks' => (bool) $this->modx->getOption('cspsecurity.allow_stripe_webhooks', null, false),
            'allow_unsafe_eval' => (bool) $this->modx->getOption('cspsecurity.allow_unsafe_eval', null, false),
            'allow_unsafe_inline_styles' => (bool) $this->modx->getOption('cspsecurity.allow_unsafe_inline_styles', null, false),
            'object_src' => $this->modx->getOption('cspsecurity.object_src', null, 'none'), // 'none' or 'self'
            'custom_style_hashes' => $this->modx->getOption('cspsecurity.custom_style_hashes', null, ''),
            'custom_script_hashes' => $this->modx->getOption('cspsecurity.custom_script_hashes', null, '')
        ];
        
        // Parse custom domains
        if (!empty($this->config['custom_domains'])) {
            $domains = array_map('trim', explode(',', $this->config['custom_domains']));
            $this->allowedDomains = array_filter($domains, function($domain) {
                return !empty($domain) && $this->isValidDomain($domain);
            });
            
            if ($this->config['debug_mode']) {
                $this->modx->log(modX::LOG_LEVEL_INFO, 'CSP Security: Loaded custom domains: ' . implode(', ', $this->allowedDomains));
            }
        }
    }

    /**
     * Main processing method
     */
    public function process()
    {
        if (!$this->config['enabled']) {
            return;
        }

        $content = $this->modx->resource->_output;
        if (empty($content)) {
            return;
        }

        try {
            // Check if Stripe is being used on this page
            $hasStripe = $this->detectStripeUsage($content);
            
            // Process the content
            $processedContent = $this->processContent($content, $hasStripe);
            
            // Set CSP header (with error handling to prevent 502)
            $this->setCSPHeader($hasStripe);
            
            // Update the output
            $this->modx->resource->_output = $processedContent;
            
            if ($this->config['debug_mode']) {
                $this->modx->log(modX::LOG_LEVEL_INFO, 'CSP Security: Processed ' . count($this->nonces) . ' elements' . ($hasStripe ? ' (Stripe detected)' : ''));
            }
            
        } catch (Exception $e) {
            $this->modx->log(modX::LOG_LEVEL_ERROR, 'CSP Security Error: ' . $e->getMessage());
            // Continue without CSP to prevent 502 errors
        } catch (Error $e) {
            $this->modx->log(modX::LOG_LEVEL_ERROR, 'CSP Security Fatal Error: ' . $e->getMessage());
            // Continue without CSP to prevent 502 errors
        }
    }

    /**
     * Detect if Stripe is being used on the current page
     * 
     * @param string $content
     * @return bool
     */
    private function detectStripeUsage($content)
    {
        if (!$this->config['enable_stripe']) {
            return false;
        }

        // Check for Stripe script includes
        $stripePatterns = [
            '/stripe\.com\/v[0-9]+\/stripe\.js/',
            '/js\.stripe\.com/',
            '/checkout\.stripe\.com/',
            '/Stripe\s*\(/i',
            '/stripe\s*=/i',
            '/new\s+Stripe/i',
            '/stripe\.createToken/i',
            '/stripe\.createPayment/i',
            '/stripe\.confirmPayment/i',
            '/stripe\.elements/i',
            '/data-stripe/i'
        ];

        foreach ($stripePatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                if ($this->config['debug_mode']) {
                    $this->modx->log(modX::LOG_LEVEL_INFO, 'CSP Security: Stripe usage detected with pattern: ' . $pattern);
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Process HTML content to add nonces
     * 
     * @param string $content
     * @param bool $hasStripe
     * @return string
     */
    private function processContent($content, $hasStripe = false)
    {
        // Add nonces to script tags
        $content = preg_replace_callback(
            '/<script(?=[^>]*(?:src=|>))[^>]*>/i',
            function($matches) use ($hasStripe) {
                return $this->addScriptNonce($matches, $hasStripe);
            },
            $content
        );

        // Add nonces to style tags
        $content = preg_replace_callback(
            '/<style[^>]*>/i',
            [$this, 'addStyleNonce'],
            $content
        );

        // Process Stripe-specific elements if detected
        if ($hasStripe) {
            $content = $this->processStripeElements($content);
        }

        return $content;
    }

    /**
     * Process Stripe-specific elements
     * 
     * @param string $content
     * @return string
     */
    private function processStripeElements($content)
    {
        // Add nonces to Stripe card elements and forms
        $content = preg_replace_callback(
            '/<div[^>]*id=["\']?stripe-card["\']?[^>]*>/i',
            [$this, 'addStripeNonce'],
            $content
        );

        $content = preg_replace_callback(
            '/<form[^>]*data-stripe[^>]*>/i',
            [$this, 'addStripeNonce'],
            $content
        );

        return $content;
    }

    /**
     * Add nonce to Stripe elements
     * 
     * @param array $matches
     * @return string
     */
    private function addStripeNonce($matches)
    {
        $tag = $matches[0];
        $nonce = $this->generateSecureNonce($tag . '_stripe');
        $this->nonces[] = $nonce;

        // Add nonce attribute if it doesn't exist
        if (!preg_match('/nonce=/', $tag)) {
            $tag = str_replace('>', " nonce=\"{$nonce}\">", $tag);
        }

        return $tag;
    }

    /**
     * Add nonce to script tag
     * 
     * @param array $matches
     * @param bool $hasStripe
     * @return string
     */
    private function addScriptNonce($matches, $hasStripe = false)
    {
        $tag = $matches[0];
        
        // Generate new nonce
        $nonce = $this->generateSecureNonce($tag);
        $this->nonces[] = $nonce;

        // Check if this is a Stripe script
        $isStripeScript = $hasStripe && (
            preg_match('/stripe\.com|js\.stripe\.com|checkout\.stripe\.com/', $tag) ||
            preg_match('/src=["\'][^"\']*stripe[^"\']*["\']/', $tag)
        );

        // Check if nonce already exists
        if (preg_match('/nonce=["\']([^"\']+)["\']/', $tag, $nonceMatches)) {
            if ($this->config['override_existing_nonces'] && !$isStripeScript) {
                // Replace existing nonce with our generated one (but not for Stripe scripts)
                $existingNonce = $nonceMatches[0];
                $tag = str_replace($existingNonce, "nonce=\"{$nonce}\"", $tag);
                
                if ($this->config['debug_mode']) {
                    $this->modx->log(modX::LOG_LEVEL_INFO, "CSP Security: Replaced existing script nonce '{$nonceMatches[1]}' with '{$nonce}'");
                }
            } else {
                // Use existing nonce and add to our list for CSP header
                $existingNonce = $nonceMatches[1];
                $this->nonces[count($this->nonces) - 1] = $existingNonce;
                
                if ($this->config['debug_mode']) {
                    $this->modx->log(modX::LOG_LEVEL_INFO, "CSP Security: Kept existing script nonce '{$existingNonce}'" . ($isStripeScript ? ' (Stripe script)' : ''));
                }
                
                return $tag;
            }
        } else {
            // Insert nonce attribute for tags without existing nonce
            $tag = str_replace('<script', "<script nonce=\"{$nonce}\"", $tag);
        }

        return $tag;
    }

    /**
     * Add nonce to style tag
     * 
     * @param array $matches
     * @return string
     */
    private function addStyleNonce($matches)
    {
        $tag = $matches[0];
        
        // Generate new nonce
        $nonce = $this->generateSecureNonce($tag);
        $this->nonces[] = $nonce;

        // Check if nonce already exists
        if (preg_match('/nonce=["\']([^"\']+)["\']/', $tag, $nonceMatches)) {
            if ($this->config['override_existing_nonces']) {
                // Replace existing nonce with our generated one
                $existingNonce = $nonceMatches[0];
                $tag = str_replace($existingNonce, "nonce=\"{$nonce}\"", $tag);
                
                if ($this->config['debug_mode']) {
                    $this->modx->log(modX::LOG_LEVEL_INFO, "CSP Security: Replaced existing style nonce '{$nonceMatches[1]}' with '{$nonce}'");
                }
            } else {
                // Use existing nonce and add to our list for CSP header
                $existingNonce = $nonceMatches[1];
                $this->nonces[count($this->nonces) - 1] = $existingNonce;
                
                if ($this->config['debug_mode']) {
                    $this->modx->log(modX::LOG_LEVEL_INFO, "CSP Security: Kept existing style nonce '{$existingNonce}'");
                }
                
                return $tag;
            }
        } else {
            // Insert nonce attribute for tags without existing nonce
            $tag = str_replace('<style', "<style nonce=\"{$nonce}\"", $tag);
        }

        return $tag;
    }

    /**
     * Validate and sanitize existing nonce value
     * 
     * @param string $nonce
     * @return bool
     */
    private function isValidNonce($nonce)
    {
        // Check if nonce is a valid format (alphanumeric, reasonable length)
        if (empty($nonce) || strlen($nonce) < 8 || strlen($nonce) > 64) {
            return false;
        }
        
        // Check if contains only safe characters
        if (!preg_match('/^[a-zA-Z0-9+\/=_-]+$/', $nonce)) {
            return false;
        }
        
        return true;
    }

    /**
     * Generate a cryptographically secure nonce
     * 
     * @param string $context
     * @return string
     */
    private function generateSecureNonce($context = '')
    {
        // Use only cryptographically secure random bytes — no mt_rand() or microtime()
        return bin2hex(random_bytes(16));
    }

    /**
     * Parse comma-separated CSP hashes from a system setting value.
     * Accepts formats: 'sha256-abc123', sha256-abc123
     * Returns array of quoted hash tokens ready for CSP header, e.g. ["'sha256-abc123'"]
     * 
     * @param string $raw
     * @return array
     */
    private function parseCustomHashes($raw)
    {
        if (empty($raw)) {
            return [];
        }

        $hashes = [];
        $tokens = array_map('trim', explode(',', $raw));
        foreach ($tokens as $token) {
            // Strip surrounding quotes if present
            $token = trim($token, " \t\n\r\0\x0B'\"");
            if (empty($token)) {
                continue;
            }
            // Validate format: sha256-<base64>, sha384-..., sha512-...
            if (preg_match('/^sha(256|384|512)-[A-Za-z0-9+\/=_-]+$/', $token)) {
                $hashes[] = "'{$token}'";
            } elseif ($this->config['debug_mode']) {
                $this->modx->log(modX::LOG_LEVEL_WARN, "CSP Security: Ignoring invalid custom hash: {$token}");
            }
        }

        return array_unique($hashes);
    }

    /**
     * Search for inline event handlers and create SHA256 hashes
     * 
     * @param string $content
     * @return array
     */
    private function findInlineEvents($content)
    {
        $hashes = [];
        
        // Pattern to match common inline event handlers
        $eventPattern = '/on(?:load|click|change|submit|focus|blur|keyup|keydown|mouseover|mouseout|invalid|input)="([^"]+)"/i';
        
        if (preg_match_all($eventPattern, $content, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                if (!empty($match[1])) {
                    $hash = base64_encode(hash('sha256', $match[1], true));
                    $hashes[] = $hash;
                }
            }
        }

        // Special case for common patterns
        if (strpos($content, "this.onload=null;this.media='all';") !== false) {
            $hashes[] = base64_encode(hash('sha256', "this.onload=null;this.media='all';", true));
        }

        return array_unique($hashes);
    }

    /**
     * Search for inline styles and create SHA256 hashes
     * 
     * @param string $content
     * @return array
     */
    private function findInlineStyles($content) 
    {
        $hashes = [];
        
        // Match style tags with content
        if (preg_match_all('/<style[^>]*>(.*?)<\/style>/is', $content, $matches)) {
            foreach ($matches[1] as $styleContent) {
                if (!empty($styleContent)) {
                    $hash = base64_encode(hash('sha256', trim($styleContent), true));
                    $hashes[] = $hash;
                }
            }
        }
        
        // Match inline style attributes (e.g. style="margin-left:5.33333%")
        if (preg_match_all('/style="([^"]+)"/i', $content, $matches)) {
            foreach ($matches[1] as $styleContent) {
                if (!empty($styleContent)) {
                    $hash = base64_encode(hash('sha256', trim($styleContent), true));
                    $hashes[] = $hash;
                }
            }
        }
        
        return array_unique($hashes);
    }

    /**
     * Search for external sources in content
     * 
     * @param string $content
     * @param bool $hasStripe
     * @return array
     */
    private function findExternalSources($content, $hasStripe = false)
    {
        $sources = [];
        
        // Common CDN patterns to detect
        $patterns = [
            'https://fonts.googleapis.com/',
            'https://fonts.gstatic.com/',
            'https://cdnjs.cloudflare.com/',
            'https://maxcdn.bootstrapcdn.com/',
            'https://code.jquery.com/',
            'https://stackpath.bootstrapcdn.com/',
            'https://unpkg.com/',
            'https://cdn.jsdelivr.net/'
        ];

        foreach ($patterns as $pattern) {
            if (strpos($content, $pattern) !== false) {
                $sources[] = $pattern;
            }
        }

        // Add Stripe domains if Stripe is detected and enabled
        if ($hasStripe && $this->config['enable_stripe']) {
            $sources = array_merge($sources, $this->stripeDomains);
        }

        // Add custom allowed domains
        $sources = array_merge($sources, $this->allowedDomains);

        return array_unique($sources);
    }

    /**
     * Get font-specific domains from content
     * 
     * @param string $content
     * @return array
     */
    private function getFontDomains($content)
    {
        $fontDomains = [];
        
        // Check for common font CDNs in content
        foreach ($this->commonFontDomains as $domain) {
            if (strpos($content, $domain) !== false) {
                $fontDomains[] = $domain;
            }
        }
        
        // Parse link tags for font resources
        if (preg_match_all('/<link[^>]*href=["\']([^"\']*font[^"\']*)["\'][^>]*>/i', $content, $matches)) {
            foreach ($matches[1] as $fontUrl) {
                $parsedUrl = parse_url($fontUrl);
                if ($parsedUrl && isset($parsedUrl['scheme']) && isset($parsedUrl['host'])) {
                    $fontDomain = $parsedUrl['scheme'] . '://' . $parsedUrl['host'];
                    if (!in_array($fontDomain, $fontDomains)) {
                        $fontDomains[] = $fontDomain;
                    }
                }
            }
        }
        
        // Parse @font-face rules in CSS
        if (preg_match_all('/@font-face[^}]*url\(["\']?([^"\']*)["\']?\)/i', $content, $matches)) {
            foreach ($matches[1] as $fontUrl) {
                $parsedUrl = parse_url($fontUrl);
                if ($parsedUrl && isset($parsedUrl['scheme']) && isset($parsedUrl['host'])) {
                    $fontDomain = $parsedUrl['scheme'] . '://' . $parsedUrl['host'];
                    if (!in_array($fontDomain, $fontDomains)) {
                        $fontDomains[] = $fontDomain;
                    }
                }
            }
        }
        
        // Include custom domains that might serve fonts
        foreach ($this->allowedDomains as $domain) {
            if (!in_array($domain, $fontDomains)) {
                $fontDomains[] = $domain;
            }
        }
        
        return array_unique($fontDomains);
    }

    /**
     * Get all allowed domains (external sources + custom domains)
     * 
     * @param string $content
     * @param bool $hasStripe
     * @return array
     */
    private function getAllAllowedDomains($content, $hasStripe = false)
    {
        $allDomains = [];
        
        // Get external sources found in content
        $externalSources = $this->findExternalSources($content, $hasStripe);
        $allDomains = array_merge($allDomains, $externalSources);
        
        // Always include custom domains
        $allDomains = array_merge($allDomains, $this->allowedDomains);
        
        return array_unique($allDomains);
    }

    /**
     * Set Content Security Policy header
     * 
     * @param bool $hasStripe
     */
    private function setCSPHeader($hasStripe = false)
    {
        if (headers_sent()) {
            $this->modx->log(modX::LOG_LEVEL_WARN, 'CSP Security: Headers already sent, cannot set CSP header');
            return;
        }

        try {
            $content = $this->modx->resource->_output;
            
            // Get all allowed domains (includes custom domains)
            $allAllowedDomains = $this->getAllAllowedDomains($content, $hasStripe);
            $allDomainsString = empty($allAllowedDomains) ? '' : ' ' . implode(' ', $allAllowedDomains);

            // Get font-specific domains (now includes custom domains)
            $fontDomains = $this->getFontDomains($content);
            $fontDomainsString = empty($fontDomains) ? '' : ' ' . implode(' ', $fontDomains);

            // Get inline event hashes
            $inlineHashes = $this->findInlineEvents($content);
            $hashList = '';
            if (!empty($inlineHashes)) {
                $hashList = " 'sha256-" . implode("' 'sha256-", $inlineHashes) . "'";
                if ($this->config['unsafe_hashes']) {
                    $hashList = " 'unsafe-hashes'" . $hashList;
                }
            }

            // Get inline style hashes (covers <style> tags and style="..." attributes)
            $styleHashes = $this->findInlineStyles($content);
            // Merge custom style hashes from system setting (comma-separated 'sha256-...' values)
            $customStyleHashes = $this->parseCustomHashes($this->config['custom_style_hashes']);
            $styleHashList = '';
            $allStyleHashes = array_merge(
                array_map(function($h) { return "'sha256-{$h}'"; }, $styleHashes),
                $customStyleHashes
            );
            if (!empty($allStyleHashes)) {
                // 'unsafe-hashes' is required by the CSP spec to allow hashed inline style attributes
                $styleHashList = " 'unsafe-hashes' " . implode(' ', $allStyleHashes);
            }

            // Build nonce list
            $nonceList = '';
            if (!empty($this->nonces)) {
                $nonceList = " 'nonce-" . implode("' 'nonce-", $this->nonces) . "'";
            }

            // Stripe-specific adjustments for script-src
            // Modern Stripe.js (v3+) works with nonces and does NOT require
            // 'unsafe-eval' or 'unsafe-inline'. Only the Stripe domains are needed.
            $stripeScriptAdjustments = '';

            // Merge custom script hashes from system setting (comma-separated 'sha256-...' values)
            $customScriptHashes = $this->parseCustomHashes($this->config['custom_script_hashes']);
            $customScriptHashList = empty($customScriptHashes) ? '' : ' ' . implode(' ', $customScriptHashes);

            // Build CSP directive parts
            $unsafeEval = $this->config['allow_unsafe_eval'] ? " 'unsafe-eval'" : '';
            $scriptSrc = "script-src 'self' https:{$allDomainsString}{$nonceList}{$hashList}{$customScriptHashList}{$unsafeEval}";

            // Use nonces for styles; only fall back to unsafe-inline if explicitly opted in
            if ($this->config['allow_unsafe_inline_styles']) {
                $styleSrc = "style-src 'self' 'unsafe-inline' https:{$allDomainsString}";
            } else {
                $styleSrc = "style-src 'self' https:{$allDomainsString}{$nonceList}{$styleHashList}";
            }
            $fontSrc = "font-src 'self' data: https:{$fontDomainsString}";
            
            // Don't use strict-dynamic with Stripe as it can cause issues
            if ($this->config['strict_dynamic'] && !$hasStripe) {
                $scriptSrc .= " 'strict-dynamic'";
            }

            // Prepare Stripe domains for connect-src
            $stripeConnectDomains = '';
            if ($hasStripe && $this->config['enable_stripe']) {
                $stripeConnectDomains = ' ' . implode(' ', $this->stripeDomains);
            }

            // Build base CSP directives
            $objectSrcValue = ($this->config['object_src'] === 'self') ? "'self'" : "'none'";
            $cspParts = [
                "default-src 'self'{$allDomainsString}",
                "base-uri 'self'",
                "object-src {$objectSrcValue}",
                $scriptSrc,
                $styleSrc,
                "img-src 'self' data: https:{$allDomainsString}",
                $fontSrc,
                "connect-src 'self' https:{$stripeConnectDomains}{$allDomainsString}",
                "form-action 'self'{$allDomainsString}",
                "frame-src 'self'{$allDomainsString}",
                "frame-ancestors 'self'",
            ];

            // Add Stripe-specific directives
            if ($hasStripe && $this->config['enable_stripe']) {
                // Override frame-src with Stripe domains
                // Remove the default frame-src and add Stripe-specific one
                $cspParts = array_filter($cspParts, function($part) {
                    return strpos($part, 'frame-src') !== 0;
                });
                $cspParts[] = "frame-src 'self' https://checkout.stripe.com https://js.stripe.com https://hooks.stripe.com{$allDomainsString}";
                
                // Override form-action with Stripe checkout
                if ($this->config['allow_stripe_forms']) {
                    $cspParts = array_filter($cspParts, function($part) {
                        return strpos($part, 'form-action') !== 0;
                    });
                    $cspParts[] = "form-action 'self' https://checkout.stripe.com{$allDomainsString}";
                }
                
                // Add child-src for older browser compatibility
                $cspParts[] = "child-src 'self' https://checkout.stripe.com https://js.stripe.com";
            }

            // Add report URI if configured
            $rawReportUri = $this->config['report_uri'];
            if (!empty($rawReportUri)) {
                $reportUri = trim($rawReportUri);
                // Accept full URLs or absolute paths (starting with /)
                if (filter_var($reportUri, FILTER_VALIDATE_URL) ||
                    (strpos($reportUri, '/') === 0 && preg_match('#^/[a-zA-Z0-9/_.\-]+$#', $reportUri))
                ) {
                    $cspParts[] = "report-uri {$reportUri}";
                } else {
                    $this->modx->log(modX::LOG_LEVEL_WARN, "CSP Security: Invalid report_uri value: '{$reportUri}'");
                }
            }

            // Clean up any double spaces and build final header
            $cspParts = array_map(function($part) {
                return preg_replace('/\s+/', ' ', trim($part));
            }, $cspParts);

            $cspHeader = implode('; ', array_filter($cspParts));
            
            // Validate header length (some servers have limits)
            if (strlen($cspHeader) > 8192) {
                $this->modx->log(modX::LOG_LEVEL_WARN, 'CSP Security: CSP header is very long (' . strlen($cspHeader) . ' characters), this might cause issues');
            }
            
            // Set the header (use report-only mode for debugging if configured)
            // $headerName = $this->config['report_only'] ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
            $headerName = 'Content-Security-Policy';
            header("{$headerName}: {$cspHeader}");
            
            if ($this->config['debug_mode']) {
                $debugInfo = "CSP Header" . ($hasStripe ? ' (Stripe enabled)' : '') . ": {$cspHeader}";
                if (!empty($this->allowedDomains)) {
                    $debugInfo .= "\nCustom domains included: " . implode(', ', $this->allowedDomains);
                }
                $debugInfo .= "\nHeader length: " . strlen($cspHeader) . " characters";
                $this->modx->log(modX::LOG_LEVEL_INFO, $debugInfo);
            }
            
        } catch (Exception $e) {
            $this->modx->log(modX::LOG_LEVEL_ERROR, 'CSP Security: Error setting CSP header: ' . $e->getMessage());
            // Don't set any CSP header if there's an error to avoid 502
        }
    }

    /**
     * Validate domain format
     * 
     * @param string $domain
     * @return bool
     */
    private function isValidDomain($domain)
    {
        // Basic domain validation - allow both full URLs and protocol-relative
        if (preg_match('/^https?:\/\/[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]/', $domain)) {
            return true;
        }
        
        // Allow wildcard subdomains like *.example.com
        if (preg_match('/^\*\.[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/', $domain)) {
            return true;
        }
        
        return false;
    }
}

// Initialize and run the handler
if ($modx->event->name === 'OnWebPagePrerender') {
    $handler = new CSPSecurityHandler($modx);
    $handler->process();
}