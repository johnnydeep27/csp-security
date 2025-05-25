<?php
/**
 * CSP Security Plugin for MODX
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
            'override_existing_nonces' => (bool) $this->modx->getOption('cspsecurity.override_existing_nonces', null, true)
        ];
        
        // Parse custom domains
        if (!empty($this->config['custom_domains'])) {
            $domains = array_map('trim', explode(',', $this->config['custom_domains']));
            $this->allowedDomains = array_filter($domains, function($domain) {
                return !empty($domain) && $this->isValidDomain($domain);
            });
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
            // Process the content
            $processedContent = $this->processContent($content);
            
            // Set CSP header
            $this->setCSPHeader();
            
            // Update the output
            $this->modx->resource->_output = $processedContent;
            
            if ($this->config['debug_mode']) {
                $this->modx->log(modX::LOG_LEVEL_INFO, 'CSP Security: Processed ' . count($this->nonces) . ' elements');
            }
            
        } catch (Exception $e) {
            $this->modx->log(modX::LOG_LEVEL_ERROR, 'CSP Security Error: ' . $e->getMessage());
        }
    }

    /**
     * Process HTML content to add nonces
     * 
     * @param string $content
     * @return string
     */
    private function processContent($content)
    {
        // Add nonces to script tags
        $content = preg_replace_callback(
            '/<script(?=[^>]*(?:src=|>))[^>]*>/i',
            [$this, 'addScriptNonce'],
            $content
        );

        // Add nonces to style tags
        $content = preg_replace_callback(
            '/<style[^>]*>/i',
            [$this, 'addStyleNonce'],
            $content
        );

        return $content;
    }

    /**
     * Add nonce to script tag
     * 
     * @param array $matches
     * @return string
     */
    private function addScriptNonce($matches)
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
                    $this->modx->log(modX::LOG_LEVEL_INFO, "CSP Security: Replaced existing script nonce '{$nonceMatches[1]}' with '{$nonce}'");
                }
            } else {
                // Use existing nonce and add to our list for CSP header
                $existingNonce = $nonceMatches[1];
                $this->nonces[count($this->nonces) - 1] = $existingNonce; // Replace the generated nonce with existing one
                
                if ($this->config['debug_mode']) {
                    $this->modx->log(modX::LOG_LEVEL_INFO, "CSP Security: Kept existing script nonce '{$existingNonce}'");
                }
                
                return $tag; // Return original tag
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
                $this->nonces[count($this->nonces) - 1] = $existingNonce; // Replace the generated nonce with existing one
                
                if ($this->config['debug_mode']) {
                    $this->modx->log(modX::LOG_LEVEL_INFO, "CSP Security: Kept existing style nonce '{$existingNonce}'");
                }
                
                return $tag; // Return original tag
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
        // Use cryptographically secure random bytes
        $randomBytes = bin2hex(random_bytes(16));
        
        // Add context-specific hash for uniqueness
        $contextHash = hash('sha256', $context . microtime(true) . mt_rand());
        
        // Combine and create final nonce
        $nonce = substr(hash('sha256', $randomBytes . $contextHash), 0, 32);
        
        return $nonce;
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
        $eventPattern = '/on(?:load|click|change|submit|focus|blur|keyup|keydown|mouseover|mouseout)="([^"]+)"/i';
        
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
        
        // Match style attributes
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
     * @return array
     */
    private function findExternalSources($content)
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

        // Add custom allowed domains
        $sources = array_merge($sources, $this->allowedDomains);

        return array_unique($sources);
    }

    /**
     * Set Content Security Policy header
     */
    private function setCSPHeader()
    {
        if (headers_sent()) {
            $this->modx->log(modX::LOG_LEVEL_WARN, 'CSP Security: Headers already sent, cannot set CSP header');
            return;
        }

        $content = $this->modx->resource->_output;
        
        // Get external sources
        $externalSources = $this->findExternalSources($content);
        $sourcesList = empty($externalSources) ? '' : ' ' . implode(' ', $externalSources);

        // Get inline event hashes
        $inlineHashes = $this->findInlineEvents($content);
        $hashList = '';
        if (!empty($inlineHashes)) {
            $hashList = " 'sha256-" . implode("' 'sha256-", $inlineHashes) . "'";
            if ($this->config['unsafe_hashes']) {
                $hashList = " 'unsafe-hashes'" . $hashList;
            }
        }

        // Get inline style hashes
        $styleHashes = $this->findInlineStyles($content);
        $styleHashList = '';
        if (!empty($styleHashes)) {
            $styleHashList = " 'sha256-" . implode("' 'sha256-", $styleHashes) . "'";
        }

        // Build nonce list
        $nonceList = '';
        if (!empty($this->nonces)) {
            $nonceList = " 'nonce-" . implode("' 'nonce-", $this->nonces) . "'";
        }

        // Build CSP directive parts
        $scriptSrc = "script-src 'self' https:{$sourcesList}{$nonceList}{$hashList}";
        $styleSrc = "style-src 'self' https:{$sourcesList}{$nonceList}{$styleHashList}";
        
        if ($this->config['strict_dynamic']) {
            $scriptSrc .= " 'strict-dynamic'";
        }

        // Build full CSP header
        $cspParts = [
            "default-src 'self'",
            "base-uri 'self'{$sourcesList} data:",
            "object-src 'none'",
            $scriptSrc,
            $styleSrc,
            "img-src 'self' data: https:",
            "font-src 'self' data: https:",
            "connect-src 'self' https:",
            "frame-ancestors 'self'"
        ];

        // Add report URI if configured
        if (!empty($this->config['report_uri'])) {
            $reportUri = filter_var($this->config['report_uri'], FILTER_SANITIZE_URL);
            if (filter_var($reportUri, FILTER_VALIDATE_URL)) {
                $cspParts[] = "report-uri {$reportUri}";
            }
        }

        $cspHeader = implode('; ', $cspParts);
        
        // Set the header
        header("Content-Security-Policy: {$cspHeader}");
        
        if ($this->config['debug_mode']) {
            $this->modx->log(modX::LOG_LEVEL_INFO, "CSP Header: {$cspHeader}");
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
        // Basic domain validation
        if (preg_match('/^https?:\/\/[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}/', $domain)) {
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