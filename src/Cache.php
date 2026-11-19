<?php

namespace DevGuard;

/**
 * DevGuard Status Transient Cache (PHP)
 * Provides in-memory and atomic file-based caching with TTL for PHP environments.
 */
class Cache
{
    /**
     * @var array<string, array{data: mixed, timestamp: int, ttl: int}>
     */
    private static array $memoryCache = [];

    private int $defaultTtl;
    private ?string $cacheDir;

    /**
     * @param int $defaultTtl Default TTL in seconds (default 60s)
     * @param string|null $cacheDir Directory for persistent file cache (null = sys_get_temp_dir())
     */
    public function __construct(int $defaultTtl = 60, ?string $cacheDir = null)
    {
        $this->defaultTtl = max(1, $defaultTtl);
        $this->cacheDir = $cacheDir !== null ? rtrim($cacheDir, '/\\') : sys_get_temp_dir();
    }

    /**
     * Retrieves cached entry for a given key.
     *
     * @param string $key
     * @return array{data: mixed, isFresh: bool}|null
     */
    public function get(string $key): ?array
    {
        $now = time();

        // 1. Check in-memory static cache
        if (isset(self::$memoryCache[$key])) {
            $mem = self::$memoryCache[$key];
            $isFresh = ($now - $mem['timestamp']) < $mem['ttl'];
            return [
                'data' => $mem['data'],
                'isFresh' => $isFresh,
            ];
        }

        // 2. Check filesystem cache
        $filePath = $this->getCacheFilePath($key);
        if (!file_exists($filePath)) {
            return null;
        }

        $raw = @file_get_contents($filePath);
        if ($raw === false || $raw === '') {
            return null;
        }

        $entry = @json_decode($raw, true);
        if (!is_array($entry) || !isset($entry['timestamp'], $entry['data'], $entry['ttl'])) {
            return null;
        }

        $isFresh = ($now - (int)$entry['timestamp']) < (int)$entry['ttl'];

        // Hydrate memory cache
        self::$memoryCache[$key] = [
            'data' => $entry['data'],
            'timestamp' => (int)$entry['timestamp'],
            'ttl' => (int)$entry['ttl'],
        ];

        return [
            'data' => $entry['data'],
            'isFresh' => $isFresh,
        ];
    }

    /**
     * Writes data to transient cache.
     *
     * @param string $key
     * @param mixed $data
     * @param int|null $ttlSeconds
     * @return void
     */
    public function set(string $key, $data, ?int $ttlSeconds = null): void
    {
        $ttl = $ttlSeconds !== null ? max(1, $ttlSeconds) : $this->defaultTtl;
        $now = time();

        // 1. Store in memory
        self::$memoryCache[$key] = [
            'data' => $data,
            'timestamp' => $now,
            'ttl' => $ttl,
        ];

        // 2. Persist to file
        $filePath = $this->getCacheFilePath($key);
        $payload = [
            'key' => $key,
            'data' => $data,
            'timestamp' => $now,
            'ttl' => $ttl,
        ];

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($json !== false) {
            @file_put_contents($filePath, $json, LOCK_EX);
        }
    }

    /**
     * Clears cached entry or all memory cache.
     *
     * @param string|null $key
     * @return void
     */
    public function clear(?string $key = null): void
    {
        if ($key !== null) {
            unset(self::$memoryCache[$key]);
            $filePath = $this->getCacheFilePath($key);
            if (file_exists($filePath)) {
                @unlink($filePath);
            }
        } else {
            self::$memoryCache = [];
        }
    }

    private function getCacheFilePath(string $key): string
    {
        $safeHash = md5($key);
        return $this->cacheDir . DIRECTORY_SEPARATOR . 'devguard_cache_' . $safeHash . '.json';
    }
}
