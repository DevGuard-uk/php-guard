<?php

namespace DevGuard;

/**
 * DevGuard Domain Matcher (PHP)
 * Validates incoming request hostnames against project allowedDomains allowlists.
 * Enforces strict wildcard subdomain matching, port stripping, and header spoofing defense.
 */
class DomainMatcher
{
    /**
     * Normalizes a hostname or domain string:
     * - Strips leading/trailing whitespace
     * - Converts to lower-case
     * - Strips ports (including IPv6 [::1]:port notation)
     * - Removes trailing FQDN dot (e.g. 'example.com.' -> 'example.com')
     * - Rejects header injection characters (CRLF, slashes, URI components, '@')
     *
     * @param string|null $rawHost
     * @return string Normalized hostname, or '' if invalid/spoofed
     */
    public static function normalizeHost($rawHost): string
    {
        if ($rawHost === null) {
            return '';
        }
        $str = strtolower(trim((string)$rawHost));
        if ($str === '') {
            return '';
        }

        // Reject invalid / spoofed characters
        if (preg_match('/[\r\n\0\/\s\\\\?#@]/', $str)) {
            return '';
        }

        // Handle IPv6 bracket notation [::1]:8080
        if (strpos($str, '[') === 0) {
            $endBracket = strpos($str, ']');
            if ($endBracket !== false) {
                return substr($str, 1, $endBracket - 1);
            }
        }

        // Strip port if present
        $colonIdx = strpos($str, ':');
        if ($colonIdx !== false) {
            $str = substr($str, 0, $colonIdx);
        }

        // Strip trailing dot
        if (substr($str, -1) === '.') {
            $str = substr($str, 0, -1);
        }

        return $str;
    }

    /**
     * Validates whether a domain pattern is valid for storage in allowedDomains.
     *
     * @param string|null $pattern
     * @return bool
     */
    public static function isValidDomainPattern($pattern): bool
    {
        if (!is_string($pattern)) {
            return false;
        }
        $trimmed = trim($pattern);
        if ($trimmed === '' || strlen($trimmed) > 253) {
            return false;
        }

        // Handle port if provided
        $candidate = $trimmed;
        if (strpos($candidate, ':') !== false) {
            $parts = explode(':', $candidate);
            if (count($parts) === 2 && ctype_digit($parts[1])) {
                $candidate = $parts[0];
            } else {
                return false;
            }
        }

        $normalized = self::normalizeHost($candidate);
        if ($normalized === '') {
            return false;
        }

        if ($normalized === 'localhost' || $normalized === '127.0.0.1' || $normalized === '::1') {
            return true;
        }

        $host = strpos($normalized, '*.') === 0 ? substr($normalized, 2) : $normalized;
        if ($host === '' || strpos($host, '*') !== false) {
            return false;
        }

        return (bool)preg_match('/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i', $host);
    }

    /**
     * Checks whether a given request host is permitted under the allowedDomains list.
     *
     * Rules:
     * 1. If allowedDomains is empty or null, access is permitted (domain lock disabled).
     * 2. Wildcard rule `*.example.com` matches `example.com` and `sub.example.com` or `a.b.example.com`.
     * 3. Wildcard rule NEVER matches suffix collisions like `example.com.evil.io` or `fakeexample.com`.
     * 4. Exact domain rules match normalized host strictly.
     * 5. Ports are ignored during matching (e.g. `example.com:3000` matches `example.com`).
     *
     * @param string $host Incoming host from request
     * @param array|string|null $allowedDomains Allowed domains from project
     * @return bool
     */
    public static function isDomainAllowed(string $host, $allowedDomains): bool
    {
        if ($allowedDomains === null || $allowedDomains === '' || $allowedDomains === []) {
            return true;
        }

        $list = [];
        if (is_array($allowedDomains)) {
            $list = $allowedDomains;
        } elseif (is_string($allowedDomains)) {
            $parts = explode(',', $allowedDomains);
            foreach ($parts as $p) {
                $trimmed = trim($p);
                if ($trimmed !== '') {
                    $list[] = $trimmed;
                }
            }
        }

        if (count($list) === 0) {
            return true;
        }

        $target = self::normalizeHost($host);
        if ($target === '') {
            return false;
        }

        foreach ($list as $rawPattern) {
            if (!is_string($rawPattern)) {
                continue;
            }
            $pat = strtolower(trim($rawPattern));
            if ($pat === '') {
                continue;
            }

            if ($pat === '*') {
                return true;
            }

            // Wildcard matching e.g. *.example.com
            if (strpos($pat, '*.') === 0) {
                $baseDomain = self::normalizeHost(substr($pat, 2));
                if ($baseDomain === '') {
                    continue;
                }

                // Exact match with root domain (e.g. example.com matches *.example.com)
                if ($target === $baseDomain) {
                    return true;
                }

                // Subdomain match (must strictly have a dot separator)
                $suffix = '.' . $baseDomain;
                $len = strlen($suffix);
                if (substr($target, -$len) === $suffix) {
                    return true;
                }
                continue;
            }

            // Exact match
            $normalizedPattern = self::normalizeHost($pat);
            if ($normalizedPattern !== '' && $target === $normalizedPattern) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extracts the client request host securely, preventing header injection and spoofing.
     *
     * @param array|null $server Server environment array (defaults to $_SERVER)
     * @param bool $trustProxy Whether to trust X-Forwarded-Host header
     * @return string Normalized host
     */
    public static function extractRequestHost(?array $server = null, bool $trustProxy = false): string
    {
        $server = $server ?? $_SERVER;
        $candidate = '';

        if ($trustProxy && !empty($server['HTTP_X_FORWARDED_HOST'])) {
            $xForwardedHost = (string)$server['HTTP_X_FORWARDED_HOST'];
            $parts = explode(',', $xForwardedHost);
            $candidate = trim($parts[0]);
        }

        if ($candidate === '' && !empty($server['HTTP_HOST'])) {
            $candidate = (string)$server['HTTP_HOST'];
        }

        if ($candidate === '' && !empty($server['SERVER_NAME'])) {
            $candidate = (string)$server['SERVER_NAME'];
        }

        return self::normalizeHost($candidate);
    }
}
