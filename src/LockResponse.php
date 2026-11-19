<?php

namespace DevGuard;

/**
 * DevGuard Web Lock Response & Path Allowlist (PHP)
 * Provides SEO-safe HTTP 503 Service Unavailable responses, path bypasses, and JSON lock envelopes.
 */
class LockResponse
{
    public const DEFAULT_ALLOWED_PATHS = [
        '/health',
        '/api/health',
        '/.well-known',
        '/favicon.ico',
        '/robots.txt',
        '/sitemap.xml',
    ];

    /**
     * Checks whether the incoming pathname is exempt from lock enforcement (health checks, well-known certs, etc.)
     *
     * @param string|null $pathname
     * @param array $customAllowedPaths
     * @return bool
     */
    public static function isPathAllowed(?string $pathname, array $customAllowedPaths = []): bool
    {
        if ($pathname === null || $pathname === '') {
            return false;
        }

        $normalized = strpos($pathname, '/') === 0 ? $pathname : '/' . $pathname;

        // Check default bypass paths
        foreach (self::DEFAULT_ALLOWED_PATHS as $def) {
            if ($normalized === $def || strpos($normalized, $def . '/') === 0) {
                return true;
            }
        }

        // Check custom allowed paths
        foreach ($customAllowedPaths as $rule) {
            if (!is_string($rule)) {
                continue;
            }
            // If regex pattern (e.g. #^/api/webhook#)
            if (strlen($rule) > 2 && ($rule[0] === '/' || $rule[0] === '#' || $rule[0] === '~') && substr($rule, -1) === $rule[0]) {
                if (@preg_match($rule, $normalized)) {
                    return true;
                }
            } else {
                $r = strpos($rule, '/') === 0 ? $rule : '/' . $rule;
                if ($normalized === $r || strpos($normalized, $r . '/') === 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Produces standard HTTP 503 headers for SEO-safe maintenance.
     *
     * @param int $retryAfter Seconds before client should retry
     * @return array<string, string>
     */
    public static function getLockHeaders(int $retryAfter = 3600): array
    {
        return [
            'Retry-After' => (string)$retryAfter,
            'X-Robots-Tag' => 'noindex, nofollow, noarchive',
            'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma' => 'no-cache',
            'Expires' => '0',
            'X-DevGuard-Lock' => 'active',
        ];
    }

    /**
     * Escapes HTML entities safely.
     *
     * @param string|null $str
     * @return string
     */
    public static function escapeHtml(?string $str): string
    {
        if ($str === null) {
            return '';
        }
        return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Generates an SEO-safe HTML lock page with noindex headers and contact options.
     *
     * @param array $opts
     * @return string Safe HTML document
     */
    public static function generateLockHtml(array $opts = []): string
    {
        $title = self::escapeHtml($opts['title'] ?? 'Service Temporarily Unavailable');
        $message = self::escapeHtml(
            $opts['message'] ??
            'This application is temporarily unavailable due to administrative service suspension. Please contact support or check back later.'
        );
        $appName = self::escapeHtml($opts['appName'] ?? 'DevGuard Protected Application');
        $retryAfter = (int)($opts['retryAfter'] ?? 3600);
        if ($retryAfter <= 0) {
            $retryAfter = 3600;
        }

        $contactLinks = [];
        if (!empty($opts['contactEmail'])) {
            $email = self::escapeHtml($opts['contactEmail']);
            $contactLinks[] = '<a class="dg-btn dg-btn-secondary" href="mailto:' . $email . '">Contact Support (' . $email . ')</a>';
        }
        if (!empty($opts['contactWhatsapp'])) {
            $cleanWa = preg_replace('/[^\d+]/', '', (string)$opts['contactWhatsapp']);
            $wa = self::escapeHtml($cleanWa);
            $contactLinks[] = '<a class="dg-btn dg-btn-secondary" href="https://wa.me/' . $wa . '" target="_blank" rel="noopener">WhatsApp Support</a>';
        }
        if (!empty($opts['contactPhone'])) {
            $phone = self::escapeHtml($opts['contactPhone']);
            $contactLinks[] = '<a class="dg-btn dg-btn-secondary" href="tel:' . $phone . '">Call Support</a>';
        }

        $contactHtml = implode("\n", $contactLinks);

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex, nofollow, noarchive" />
  <meta http-equiv="refresh" content="{$retryAfter}" />
  <title>{$title}</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111726;
      --border: #1f293d;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #ef4444;
      --accent-glow: rgba(239, 68, 68, 0.15);
      --btn-bg: #1e293b;
      --btn-hover: #334155;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 20%, #151e33 0%, var(--bg) 100%);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .dg-container {
      max-width: 540px;
      width: 100%;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 1rem;
      padding: 2.5rem 2rem;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6), 0 0 40px var(--accent-glow);
      text-align: center;
    }
    .dg-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(239, 68, 68, 0.12);
      color: var(--accent);
      border: 1px solid rgba(239, 68, 68, 0.25);
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
      margin-bottom: 1.25rem;
    }
    .dg-badge::before {
      content: "";
      width: 6px;
      height: 6px;
      background: var(--accent);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--accent);
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 700;
      margin-bottom: 0.75rem;
      color: var(--text-main);
      line-height: 1.3;
    }
    .dg-app {
      font-size: 0.875rem;
      color: var(--text-muted);
      margin-bottom: 1.5rem;
    }
    .dg-message {
      font-size: 0.95rem;
      color: #cbd5e1;
      line-height: 1.6;
      margin-bottom: 2rem;
      background: rgba(255, 255, 255, 0.03);
      padding: 1rem 1.25rem;
      border-radius: 0.5rem;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }
    .dg-actions {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .dg-btn {
      display: inline-block;
      width: 100%;
      padding: 0.75rem 1.25rem;
      font-size: 0.875rem;
      font-weight: 600;
      text-decoration: none;
      border-radius: 0.5rem;
      transition: all 0.2s ease;
      cursor: pointer;
    }
    .dg-btn-secondary {
      background: var(--btn-bg);
      color: var(--text-main);
      border: 1px solid var(--border);
    }
    .dg-btn-secondary:hover {
      background: var(--btn-hover);
      border-color: #475569;
    }
    .dg-footer {
      margin-top: 2rem;
      font-size: 0.75rem;
      color: #64748b;
    }
  </style>
</head>
<body>
  <div class="dg-container">
    <div class="dg-badge">HTTP 503 · Service Locked</div>
    <h1>{$title}</h1>
    <div class="dg-app">Protected: {$appName}</div>
    <div class="dg-message">{$message}</div>
    <div class="dg-actions">
      {$contactHtml}
    </div>
    <div class="dg-footer">
      Secured by DevGuard Protection Framework
    </div>
  </div>
</body>
</html>
HTML;
    }

    /**
     * Determines whether the request is an API request expecting JSON.
     *
     * @param array|null $server Defaults to $_SERVER
     * @return bool
     */
    public static function isApiRequest(?array $server = null): bool
    {
        $server = $server ?? $_SERVER;
        $accept = (string)($server['HTTP_ACCEPT'] ?? '');
        $uri = (string)($server['REQUEST_URI'] ?? '');

        if (strpos($accept, 'application/json') !== false) {
            return true;
        }

        if (strpos($uri, '/api/') !== false || strpos($uri, '/wp-json/') !== false) {
            return true;
        }

        return false;
    }

    /**
     * Sends HTTP 503 lock response and terminates script execution.
     *
     * @param array $opts
     * @param bool $isJson
     * @param bool $terminate
     * @return void
     */
    public static function sendLockResponse(array $opts = [], bool $isJson = false, bool $terminate = true): void
    {
        if (!headers_sent()) {
            http_response_code(503);
            $headers = self::getLockHeaders((int)($opts['retryAfter'] ?? 3600));
            foreach ($headers as $k => $v) {
                header("{$k}: {$v}");
            }
        }

        if ($isJson) {
            if (!headers_sent()) {
                header('Content-Type: application/json; charset=utf-8');
            }
            $payload = [
                'error' => 'service_locked',
                'code' => $opts['code'] ?? 'DEVGUARD_LOCKED',
                'title' => $opts['title'] ?? 'Service Temporarily Locked',
                'message' => $opts['message'] ?? 'This service is currently unavailable.',
                'retryAfter' => (int)($opts['retryAfter'] ?? 3600),
                'appName' => $opts['appName'] ?? null,
            ];
            echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } else {
            if (!headers_sent()) {
                header('Content-Type: text/html; charset=utf-8');
            }
            echo self::generateLockHtml($opts);
        }

        if ($terminate) {
            exit;
        }
    }
}
