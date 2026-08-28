<?php

declare(strict_types=1);

namespace Namingo\Bind9Api;

use PDO;
use RuntimeException;

final class Database
{
    private string $driver;

    /** @param array<string, mixed> $environment */
    public function __construct(private readonly array $environment)
    {
        $driver = strtolower(trim((string) ($environment['DB_TYPE'] ?? '')));
        $this->driver = $driver === 'mariadb' ? 'mysql' : $driver;

        if (!in_array($this->driver, ['mysql', 'sqlite'], true)) {
            throw new RuntimeException('DB_TYPE must be either mysql or sqlite.');
        }
    }

    public function driver(): string
    {
        return $this->driver;
    }

    /**
     * MySQL keeps the original Swoole PDO pool. SQLite opens a short-lived
     * connection per request so a PDO object is never shared by coroutines.
     */
    public function createPool(): ?object
    {
        if ($this->driver === 'sqlite') {
            return null;
        }

        if (!class_exists(\Swoole\Database\PDOPool::class)) {
            throw new RuntimeException('The Swoole PDO pool classes are unavailable.');
        }

        return new \Swoole\Database\PDOPool(
            (new \Swoole\Database\PDOConfig())
                ->withDriver('mysql')
                ->withHost($this->required('DB_HOST'))
                ->withPort($this->integer('DB_PORT', 3306, 1, 65535))
                ->withDbName($this->mysqlDatabaseName())
                ->withUsername($this->required('DB_USERNAME'))
                ->withPassword($this->requiredSecret('DB_PASSWORD'))
                ->withCharset('utf8mb4')
                ->withOptions([
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::ATTR_TIMEOUT => 5,
                ])
        );
    }

    /** @return PDO|\Swoole\Database\PDOProxy */
    public function acquire(?object $pool): object
    {
        if ($this->driver === 'sqlite') {
            return $this->connect();
        }

        if ($pool === null || !method_exists($pool, 'get')) {
            throw new RuntimeException('The MySQL connection pool is unavailable.');
        }

        $pdo = $pool->get();
        if (!is_object($pdo) || !method_exists($pdo, 'prepare')) {
            throw new RuntimeException('Unable to acquire a database connection.');
        }

        return $pdo;
    }

    /** @param PDO|\Swoole\Database\PDOProxy|null $pdo */
    public function release(?object $pool, ?object $pdo): void
    {
        if ($this->driver === 'mysql' && $pool !== null && $pdo !== null) {
            $pool->put($pdo);
        }
    }

    public function connect(): PDO
    {
        return $this->driver === 'sqlite'
            ? $this->connectSqlite()
            : $this->connectMysql();
    }

    /** Verify connectivity and enable WAL once during startup. */
    public function initialize(): void
    {
        $pdo = $this->connect();
        if ($this->driver === 'sqlite') {
            $pdo->exec('PRAGMA journal_mode = WAL');
        }
        $pdo->query('SELECT 1');
        foreach (['users', 'whitelist', 'zones', 'sessions'] as $table) {
            $pdo->query('SELECT 1 FROM ' . $table . ' LIMIT 0');
        }
    }

    private function connectSqlite(): PDO
    {
        $path = $this->required('DB_DATABASE');
        if (!str_starts_with($path, '/') || str_contains($path, "\0")) {
            throw new RuntimeException('DB_DATABASE must be an absolute SQLite path.');
        }

        $directory = dirname($path);
        if (!is_dir($directory) || !is_writable($directory)) {
            throw new RuntimeException('The SQLite database directory must exist and be writable.');
        }

        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $pdo->exec('PRAGMA foreign_keys = ON');
        $pdo->exec('PRAGMA busy_timeout = ' . $this->integer('DB_BUSY_TIMEOUT', 5000, 0, 60000));

        return $pdo;
    }

    private function connectMysql(): PDO
    {
        $host = $this->required('DB_HOST');
        if (preg_match('/[;\x00]/', $host)) {
            throw new RuntimeException('DB_HOST contains invalid characters.');
        }

        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            $host,
            $this->integer('DB_PORT', 3306, 1, 65535),
            $this->mysqlDatabaseName()
        );

        return new PDO($dsn, $this->required('DB_USERNAME'), $this->requiredSecret('DB_PASSWORD'), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_TIMEOUT => 5,
        ]);
    }

    private function mysqlDatabaseName(): string
    {
        $name = $this->required('DB_DATABASE');
        if (!preg_match('/^[A-Za-z0-9_$-]+$/', $name)) {
            throw new RuntimeException('DB_DATABASE contains invalid MySQL identifier characters.');
        }

        return $name;
    }

    private function required(string $key): string
    {
        $value = trim((string) ($this->environment[$key] ?? ''));
        if ($value === '') {
            throw new RuntimeException($key . ' is required.');
        }

        return $value;
    }

    private function requiredSecret(string $key): string
    {
        $value = (string) ($this->environment[$key] ?? '');
        if ($value === '') {
            throw new RuntimeException($key . ' is required.');
        }

        return $value;
    }

    private function integer(string $key, int $default, int $minimum, int $maximum): int
    {
        $raw = $this->environment[$key] ?? $default;
        $value = filter_var($raw, FILTER_VALIDATE_INT);
        if ($value === false || $value < $minimum || $value > $maximum) {
            throw new RuntimeException(sprintf('%s must be between %d and %d.', $key, $minimum, $maximum));
        }

        return $value;
    }
}
