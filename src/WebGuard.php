<?php

namespace DevGuard;

use InvalidArgumentException;

/**
 * DevGuard Web Guard Middleware (PHP)
 * Standalone middleware supporting remote project locking, domain allowlisting,
 * failSafe: 'open' policy, and SEO-safe HTTP 503 lockouts.
 */
class WebGuard
{
    private string $projectId;
    private string $apiUrl;
    private ?string $apiKey;
    private string $failSafe;
    /** @var array|string|null */
    private $allowedDomains;
    private array $allowedPaths;
    private int $cacheTtl;
    private bool $trustProxy;
    private float $timeout;
    /** @var object|callable|null */
    private $cache;
    /** @var callable|null */
    private $fetchStatus;
    /** @var callable|null */
    private $onLock;

    /**
     * @param array $config Configuration options
     * @throws InvalidArgumentException if projectId is missing
     */
    public function __construct(array $config = [])
    {
        $projectId = trim((string)($config['projectId'] ?? ''));
        if ($projectId === '') {
            throw new InvalidArgumentException('WebGuard requires a non-empty `projectId`.');
        }

        $this->projectId = $projectId;
        $this->apiUrl = rtrim((string)($config['apiUrl'] ?? getenv('DEVGUARD_API_URL') ?: 'https://api.devguard.uk'), '/');
        $sdkKey = !empty($config['sdkKey']) ? (string)$config['sdkKey'] : null;
        $legacyKey = !empty($config['apiKey']) ? (string)$config['apiKey'] : null;
        $envSdk = getenv('DEVGUARD_SDK_KEY') ?: null;
        $envApi = getenv('DEVGUARD_API_KEY') ?: null;
        $resolved = $sdkKey ?: $legacyKey ?: ($envSdk !== false && $envSdk !== '' ? (string)$envSdk : null) ?: ($envApi !== false && $envApi !== '' ? (string)$envApi : null);
        $this->apiKey = $resolved !== null && $resolved !== '' ? $resolved : null;
        $this->failSafe = ($config['failSafe'] ?? 'open') === 'closed' ? 'closed' : 'open';
        $this->allowedDomains = $config['allowedDomains'] ?? null;
        $this->allowedPaths = (array)($config['allowedPaths'] ?? []);
        $this->cacheTtl = max(5, (int)($config['cacheTtl'] ?? 60));
        $this->trustProxy = (bool)($config['trustProxy'] ?? false);
        $this->timeout = (float)($config['timeout'] ?? 3.0);
        $this->onLock = isset($config['onLock']) && is_callable($config['onLock']) ? $config['onLock'] : null;
        $this->fetchStatus = isset($config['fetchStatus']) && is_callable($config['fetchStatus']) ? $config['fetchStatus'] : null;

        if (isset($config['cache'])) {
            $this->cache = $config['cache'];
        } else {
            $this->cache = new Cache($this->cacheTtl);
        }
    }

    /**
     * Resolves project status, utilizing cached data or fetching from the DevGuard API.
     *
     * @return array
     */
    public function resolveStatus(): array
    {
        $cacheKey = 'devguard_status_' . $this->projectId;
        $cachedEntry = $this->getCache($cacheKey);

        if ($cachedEntry !== null && !empty($cachedEntry['isFresh'])) {
            return (array)$cachedEntry['data'];
        }

        try {
            $data = null;
            if ($this->fetchStatus !== null) {
                $data = call_user_func($this->fetchStatus, $this->projectId);
            } else {
                $data = $this->fetchFromApi();
            }

            if (is_array($data)) {
                $this->setCache($cacheKey, $data, $this->cacheTtl);
                return $data;
            }
        } catch (\Throwable $e) {
            // Stale cache fallback if available
            if ($cachedEntry !== null && is_array($cachedEntry['data'])) {
                return $cachedEntry['data'];
            }

            // Fail-safe open policy: do not block production traffic on network failure
            if ($this->failSafe === 'open') {
                return [
                    'status' => 'active',
                    'failSafeFallback' => true,
                    'error' => $e->getMessage(),
                ];
            }

            // Fail-safe closed policy: treat as locked
            return [
                'status' => 'locked',
                'code' => 'DEVGUARD_VERIFICATION_UNAVAILABLE',
                'title' => 'Security Verification Unavailable',
                'message' => 'Security validation service is temporarily unreachable. Please retry shortly.',
                'failSafeFallback' => true,
                'error' => $e->getMessage(),
            ];
        }

        return ['status' => 'active'];
    }

    /**
     * Checks request authorization without automatically terminating execution.
     *
     * @param string|null $host Incoming host (null = auto-detect)
     * @param string|null $uri Incoming request URI (null = auto-detect)
     * @return array Authorization result
     */
    public function check(?string $host = null, ?string $uri = null): array
    {
        // 1. Path Allowlist check
        $pathname = $uri;
        if ($pathname === null) {
            $rawUri = $_SERVER['REQUEST_URI'] ?? '/';
            $pathname = parse_url($rawUri, PHP_URL_PATH) ?: '/';
        }

        if (LockResponse::isPathAllowed($pathname, $this->allowedPaths)) {
            return [
                'allowed' => true,
                'reason' => 'path_allowed',
                'path' => $pathname,
            ];
        }

        // 2. Extract and normalize incoming host
        $targetHost = $host !== null ? DomainMatcher::normalizeHost($host) : DomainMatcher::extractRequestHost($_SERVER, $this->trustProxy);

        // 3. Resolve project status
        $project = $this->resolveStatus();

        // 4. Domain Lock check
        $effectiveDomains = $this->allowedDomains !== null ? $this->allowedDomains : ($project['allowedDomains'] ?? null);
        if ($effectiveDomains !== null && !DomainMatcher::isDomainAllowed($targetHost, $effectiveDomains)) {
            return [
                'allowed' => false,
                'reason' => 'domain_mismatch',
                'code' => 'DEVGUARD_DOMAIN_LOCKED',
                'title' => 'Domain Authorization Required',
                'message' => "The domain '{$targetHost}' is not authorized to host this application.",
                'appName' => $project['appName'] ?? null,
                'contactEmail' => $project['contactEmail'] ?? null,
                'contactPhone' => $project['contactPhone'] ?? null,
                'contactWhatsapp' => $project['contactWhatsapp'] ?? null,
                'host' => $targetHost,
                'allowedDomains' => $effectiveDomains,
                'project' => $project,
            ];
        }

        // 5. Explicit Project Locked check
        $status = strtolower((string)($project['status'] ?? 'active'));
        if ($status === 'locked' || $status === 'expired') {
            return [
                'allowed' => false,
                'reason' => 'project_locked',
                'code' => 'DEVGUARD_PROJECT_LOCKED',
                'title' => $project['title'] ?? 'Service Temporarily Locked',
                'message' => $project['message'] ?? 'This application has been locked by the developer or organization.',
                'appName' => $project['appName'] ?? null,
                'contactEmail' => $project['contactEmail'] ?? null,
                'contactPhone' => $project['contactPhone'] ?? null,
                'contactWhatsapp' => $project['contactWhatsapp'] ?? null,
                'project' => $project,
            ];
        }

        // 6. Autolock Due-Date delinquency check (if project specifies milestone due date)
        $dueAt = $project['paymentDueAt'] ?? ($project['dueAt'] ?? null);
        $autolockEnabled = !isset($project['autolock']['enabled']) || $project['autolock']['enabled'] !== false;
        if ($status === 'active' && $dueAt !== null && $autolockEnabled) {
            $dueTimestamp = is_numeric($dueAt) ? (int)$dueAt : strtotime((string)$dueAt);
            if ($dueTimestamp !== false && $dueTimestamp > 0 && time() > $dueTimestamp) {
                // If autolockState indicates autoLocked or overdue past grace
                if (!empty($project['autolockState']['autoLocked'])) {
                    return [
                        'allowed' => false,
                        'reason' => 'project_delinquent',
                        'code' => 'DEVGUARD_PROJECT_LOCKED',
                        'title' => $project['title'] ?? 'Service Temporarily Suspended',
                        'message' => $project['message'] ?? 'This website has been automatically suspended pending invoice settlement.',
                        'appName' => $project['appName'] ?? null,
                        'contactEmail' => $project['contactEmail'] ?? null,
                        'contactPhone' => $project['contactPhone'] ?? null,
                        'contactWhatsapp' => $project['contactWhatsapp'] ?? null,
                        'project' => $project,
                    ];
                }
            }
        }

        // 7. Warning state check
        if ($status === 'warning') {
            return [
                'allowed' => true,
                'warning' => true,
                'reason' => 'warning',
                'message' => $project['message'] ?? 'Administrative notice',
                'project' => $project,
            ];
        }

        return [
            'allowed' => true,
            'reason' => 'active',
            'project' => $project,
        ];
    }

    /**
     * Enforces security policy: allows valid requests to proceed, sends SEO HTTP 503 on lock.
     *
     * @param string|null $uri Request URI
     * @param string|null $host Request host
     * @param bool $autoExit Whether to send headers, render lock HTML and exit immediately
     * @return array|null Returns null if allowed, or lock response options array if locked
     */
    public function enforce(?string $uri = null, ?string $host = null, bool $autoExit = true): ?array
    {
        $result = $this->check($host, $uri);

        if (!empty($result['allowed'])) {
            if (!empty($result['warning']) && !headers_sent()) {
                header('X-DevGuard-Warning: active');
                if (!empty($result['message'])) {
                    header('X-DevGuard-Warning-Message: ' . rawurlencode((string)$result['message']));
                }
            }
            return null;
        }

        // On lock callback
        if ($this->onLock !== null) {
            call_user_func($this->onLock, $result);
        }

        if ($autoExit) {
            $isJson = LockResponse::isApiRequest($_SERVER);
            LockResponse::sendLockResponse($result, $isJson, true);
        }

        return $result;
    }

    /**
     * Internal HTTP request to DevGuard API status endpoint.
     *
     * @return array
     * @throws \RuntimeException
     */
    private function fetchFromApi(): array
    {
        $endpoints = [
            $this->apiUrl . '/api/v1/projects/' . rawurlencode($this->projectId) . '/public-status',
            $this->apiUrl . '/api/v1/projects/' . rawurlencode($this->projectId) . '/status',
        ];

        $headers = [
            'Accept: application/json',
            'User-Agent: DevGuard-PHP-Guard/1.0.0',
        ];
        if ($this->apiKey !== null && $this->apiKey !== '') {
            $headers[] = 'X-DevGuard-Key: ' . $this->apiKey;
        }

        $lastError = null;

        foreach ($endpoints as $url) {
            try {
                if (function_exists('curl_init')) {
                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, $url);
                    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, (int)ceil($this->timeout));
                    curl_setopt($ch, CURLOPT_TIMEOUT, (int)ceil($this->timeout));
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);

                    $response = curl_exec($ch);
                    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    $curlErr = curl_error($ch);
                    curl_close($ch);

                    if ($response === false || $curlErr) {
                        throw new \RuntimeException('cURL error: ' . $curlErr);
                    }

                    if ($httpCode >= 200 && $httpCode < 300) {
                        $json = json_decode((string)$response, true);
                        if (is_array($json)) {
                            return $json;
                        }
                    }
                } else {
                    // Fallback to stream context
                    $ctx = stream_context_create([
                        'http' => [
                            'method' => 'GET',
                            'header' => implode("\r\n", $headers),
                            'timeout' => $this->timeout,
                            'ignore_errors' => true,
                        ],
                    ]);
                    $response = @file_get_contents($url, false, $ctx);
                    if ($response !== false) {
                        $json = json_decode($response, true);
                        if (is_array($json)) {
                            return $json;
                        }
                    }
                }
            } catch (\Throwable $e) {
                $lastError = $e;
            }
        }

        throw new \RuntimeException('Failed to fetch DevGuard status: ' . ($lastError ? $lastError->getMessage() : 'HTTP error'));
    }

    /**
     * @param string $key
     * @return array{data: mixed, isFresh: bool}|null
     */
    private function getCache(string $key): ?array
    {
        if ($this->cache === null) {
            return null;
        }

        if (is_object($this->cache) && method_exists($this->cache, 'get')) {
            return $this->cache->get($key);
        }

        if (is_callable($this->cache)) {
            $res = call_user_func($this->cache, 'get', $key);
            if (is_array($res) && isset($res['data'])) {
                return $res;
            }
        }

        return null;
    }

    /**
     * @param string $key
     * @param mixed $data
     * @param int $ttl
     * @return void
     */
    private function setCache(string $key, $data, int $ttl): void
    {
        if ($this->cache === null) {
            return;
        }

        if (is_object($this->cache) && method_exists($this->cache, 'set')) {
            $this->cache->set($key, $data, $ttl);
            return;
        }

        if (is_callable($this->cache)) {
            call_user_func($this->cache, 'set', $key, $data, $ttl);
        }
    }
}
