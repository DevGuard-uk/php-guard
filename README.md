# DevGuard PHP Guard

Zero-dependency PHP middleware for remote project locking, invoice milestone autolock enforcement, domain allowlisting, and SEO-safe HTTP 503 maintenance pages.

## Installation

```bash
composer require devguard/php-guard
```

## Quick Start

```php
use DevGuard\WebGuard;

$guard = new WebGuard([
    'projectId' => 'proj_your_project_id',
    'apiUrl'    => 'https://api.devguard.uk',
    'failSafe'  => 'open', // Defaults to 'open' (never crashes production on network blips)
    'cacheTtl'  => 60,     // Cache status for 60 seconds
]);

// Enforce protection (renders HTTP 503 lock screen and exits if locked or domain unauthorized)
$guard->enforce();
```

## Standalone Check (No Auto-Exit)

```php
$result = $guard->check();

if (!$result['allowed']) {
    // Custom handling
    error_log("DevGuard locked: " . $result['reason']);
}
```

## Security Features

- **Wildcard Domain Allowlisting**: Enforces exact domains and `*.domain.com` subdomains while strictly preventing suffix/prefix spoofing attacks.
- **Fail-Safe Open**: Network timeouts and API blips will never crash your site.
- **SEO-Safe HTTP 503**: Sends `Retry-After: 3600`, `X-Robots-Tag: noindex, nofollow, noarchive`, and `Cache-Control: no-store` so search engine rankings are preserved during maintenance.
- **Zero Dependencies**: Pure PHP 7.4 - 8.4+.
