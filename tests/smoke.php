<?php

declare(strict_types=1);

use Namingo\Bind9Api\Database;

require dirname(__DIR__) . '/helpers.php';

function assertSameValue(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(sprintf(
            '%s (expected %s, got %s)',
            $message,
            var_export($expected, true),
            var_export($actual, true)
        ));
    }
}

$temporaryDirectory = sys_get_temp_dir() . '/bind9-api-test-' . bin2hex(random_bytes(6));
if (!mkdir($temporaryDirectory, 0700) && !is_dir($temporaryDirectory)) {
    throw new RuntimeException('Unable to create test directory.');
}
$databasePath = $temporaryDirectory . '/test.sqlite';

try {
    $environment = [
        'DB_TYPE' => 'sqlite',
        'DB_DATABASE' => $databasePath,
        'DB_BUSY_TIMEOUT' => '1000',
    ];
    $database = new Database($environment);
    $pdo = $database->connect();
    $schema = file_get_contents(dirname(__DIR__) . '/database/sqlite.sql');
    if ($schema === false) {
        throw new RuntimeException('Unable to read SQLite schema.');
    }
    $pdo->exec($schema);
    unset($pdo);

    $database->initialize();
    $pdo = $database->connect();
    $pdo->exec("INSERT INTO whitelist (ip_address) VALUES ('2001:db8::1')");
    assertSameValue(true, isIpWhitelisted('2001:db8::1', $pdo), 'IPv6 whitelist lookup failed');
    assertSameValue(
        true,
        isIpWhitelisted('2001:0db8:0:0:0:0:0:1', $pdo),
        'Equivalent IPv6 whitelist lookup failed'
    );

    assertSameValue('example.com', normalizeZoneName('Example.COM.'), 'Zone normalization failed');
    assertSameValue(null, normalizeZoneName('../example.com'), 'Traversal-like zone was accepted');
    assertSameValue(true, isValidRecordName('_sip._tcp'), 'Service record name was rejected');
    assertSameValue(false, isValidRecordName("www\ninclude"), 'Control character was accepted');
    assertSameValue(true, ipMatchesRange('192.0.2.10', '192.0.2.0/24'), 'IPv4 CIDR match failed');
    assertSameValue(true, ipMatchesRange('2001:db8::10', '2001:db8::/32'), 'IPv6 CIDR match failed');
    assertSameValue('2001:db8::1', normalizeIpAddress('2001:0db8:0:0:0:0:0:1'), 'IPv6 normalization failed');
    $_ENV['TRUSTED_PROXIES'] = '127.0.0.1';
    $proxyRequest = (object) [
        'server' => ['remote_addr' => '127.0.0.1'],
        'header' => ['x-forwarded-for' => '2001:0db8:0:0:0:0:0:1'],
    ];
    assertSameValue('2001:db8::1', getClientIp($proxyRequest), 'Trusted proxy client IP handling failed');
    $todaySerial = gmdate('Ymd') . '01';
    assertSameValue((string) ((int) $todaySerial + 1), nextSerialNumber($todaySerial), 'SOA serial increment failed');

    assertSameValue('192.0.2.1', buildRdata('A', '192.0.2.1')->toText(), 'A RDATA build failed');
    assertSameValue(
        '10 mail.example.com.',
        buildRdata('MX', ['preference' => 10, 'exchange' => 'mail.example.com'])->toText(),
        'MX RDATA build failed'
    );
    assertSameValue(
        '2371 8 2 5E2B4D2C',
        buildRdata('DS', '2371 8 2 5E2B4D2C')->toText(),
        'DS text RDATA build failed'
    );

    // Swoole's MySQL pool returns PDOProxy rather than native PDO. Keep that
    // boundary covered without requiring a live MySQL server in this suite.
    $proxy = new class {
        public function prepare(string $query): void
        {
        }
    };
    $fakePool = new class ($proxy) {
        public ?object $released = null;

        public function __construct(private readonly object $connection)
        {
        }

        public function get(): object
        {
            return $this->connection;
        }

        public function put(object $connection): void
        {
            $this->released = $connection;
        }
    };
    $mysqlDatabase = new Database(['DB_TYPE' => 'mariadb']);
    assertSameValue('mysql', $mysqlDatabase->driver(), 'MariaDB alias was not normalized');
    assertSameValue($proxy, $mysqlDatabase->acquire($fakePool), 'PDO proxy was rejected');
    $mysqlDatabase->release($fakePool, $proxy);
    assertSameValue($proxy, $fakePool->released, 'PDO proxy was not returned to the pool');

    fwrite(STDOUT, "Smoke tests passed.\n");
} finally {
    unset($pdo, $database);
    foreach ([$databasePath, $databasePath . '-wal', $databasePath . '-shm'] as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }
    if (is_dir($temporaryDirectory)) {
        rmdir($temporaryDirectory);
    }
}
