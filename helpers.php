<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Badcow\DNS\AlignedBuilder;
use Badcow\DNS\Rdata\Factory;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Psr\Log\LoggerInterface;

function setupLogger(string $logFilePath, string $channelName = 'app'): Logger
{
    $log = new Logger($channelName);
    $level = envBoolean('DEBUG_MODE') ? Logger::DEBUG : Logger::INFO;
    $formatter = new LineFormatter(
        "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n",
        'Y-m-d H:i:s.u',
        true,
        true
    );

    $consoleHandler = new StreamHandler('php://stdout', $level);
    $consoleHandler->setFormatter($formatter);
    $log->pushHandler($consoleHandler);

    $fileHandler = new RotatingFileHandler($logFilePath, 14, $level);
    $fileHandler->setFormatter($formatter);
    $log->pushHandler($fileHandler);

    return $log;
}

function envBoolean(string $key, bool $default = false): bool
{
    if (!array_key_exists($key, $_ENV)) {
        return $default;
    }

    return filter_var($_ENV[$key], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) ?? $default;
}

function envInteger(string $key, int $default, int $minimum, int $maximum): int
{
    $value = filter_var($_ENV[$key] ?? $default, FILTER_VALIDATE_INT);
    if ($value === false || $value < $minimum || $value > $maximum) {
        throw new RuntimeException(sprintf('%s must be between %d and %d.', $key, $minimum, $maximum));
    }

    return $value;
}

function publicError(string $message, ?Throwable $exception = null): string
{
    if ($exception !== null) {
        error_log($message . ': ' . $exception->getMessage());
    }
    if ($exception !== null && envBoolean('DEBUG_MODE')) {
        return $message . ': ' . $exception->getMessage();
    }

    return $message;
}

function getClientIp(object $request): string
{
    $remoteAddress = normalizeIpAddress($request->server['remote_addr'] ?? null);
    if ($remoteAddress === null) {
        return '';
    }

    if (!isTrustedProxy($remoteAddress)) {
        return $remoteAddress;
    }

    $forwardedFor = (string) ($request->header['x-forwarded-for'] ?? '');
    $chain = [];
    foreach (explode(',', $forwardedFor) as $forwardedIp) {
        $normalized = normalizeIpAddress($forwardedIp);
        if ($normalized !== null) {
            $chain[] = $normalized;
        }
    }
    $chain[] = $remoteAddress;

    for ($index = count($chain) - 1; $index >= 0; --$index) {
        if (!isTrustedProxy($chain[$index])) {
            return $chain[$index];
        }
    }

    return $chain[0] ?? $remoteAddress;
}

function normalizeIpAddress(mixed $ip): ?string
{
    if (!is_string($ip)) {
        return null;
    }

    $packed = @inet_pton(trim($ip));
    if ($packed === false) {
        return null;
    }

    $normalized = @inet_ntop($packed);
    return $normalized === false ? null : strtolower($normalized);
}

function isTrustedProxy(string $ip): bool
{
    $ranges = array_filter(array_map('trim', explode(',', (string) ($_ENV['TRUSTED_PROXIES'] ?? ''))));
    foreach ($ranges as $range) {
        if (ipMatchesRange($ip, $range)) {
            return true;
        }
    }

    return false;
}

function ipMatchesRange(string $ip, string $range): bool
{
    if (!str_contains($range, '/')) {
        $packedIp = @inet_pton($ip);
        $packedRange = @inet_pton($range);
        return $packedIp !== false && $packedRange !== false && hash_equals($packedRange, $packedIp);
    }

    [$subnet, $prefixText] = explode('/', $range, 2);
    $packedIp = @inet_pton($ip);
    $packedSubnet = @inet_pton($subnet);
    $prefix = filter_var($prefixText, FILTER_VALIDATE_INT);
    if ($packedIp === false || $packedSubnet === false || strlen($packedIp) !== strlen($packedSubnet)) {
        return false;
    }

    $maximumBits = strlen($packedIp) * 8;
    if ($prefix === false || $prefix < 0 || $prefix > $maximumBits) {
        return false;
    }

    $wholeBytes = intdiv($prefix, 8);
    $remainingBits = $prefix % 8;
    if ($wholeBytes > 0 && substr($packedIp, 0, $wholeBytes) !== substr($packedSubnet, 0, $wholeBytes)) {
        return false;
    }
    if ($remainingBits === 0) {
        return true;
    }

    $mask = (0xff << (8 - $remainingBits)) & 0xff;
    return (ord($packedIp[$wholeBytes]) & $mask) === (ord($packedSubnet[$wholeBytes]) & $mask);
}

function isIpWhitelisted(string $ip, object $pdo): bool
{
    $ip = normalizeIpAddress($ip);
    if ($ip === null) {
        return false;
    }

    $statement = $pdo->prepare('SELECT COUNT(*) FROM whitelist WHERE ip_address = :ip');
    $statement->execute(['ip' => $ip]);
    return (int) $statement->fetchColumn() > 0;
}

function normalizeZoneName(mixed $domain): ?string
{
    if (!is_string($domain)) {
        return null;
    }

    $domain = strtolower(rtrim(trim($domain), '.'));
    if ($domain === '' || strlen($domain) > 253 || str_contains($domain, '..')) {
        return null;
    }

    foreach (explode('.', $domain) as $label) {
        if (strlen($label) > 63 || !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $label)) {
            return null;
        }
    }

    return $domain;
}

function isValidDomainName(mixed $domain): bool
{
    return normalizeZoneName($domain) !== null;
}

function isValidRecordName(mixed $name): bool
{
    if (!is_string($name)) {
        return false;
    }

    $name = rtrim(trim($name), '.');
    if ($name === '@') {
        return true;
    }
    if ($name === '' || strlen($name) > 253 || str_contains($name, '..')) {
        return false;
    }

    foreach (explode('.', $name) as $index => $label) {
        if ($index === 0 && $label === '*') {
            continue;
        }
        if (strlen($label) > 63 || !preg_match('/^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/', $label)) {
            return false;
        }
    }

    return true;
}

function normalizeTtl(mixed $ttl): ?int
{
    $value = filter_var($ttl, FILTER_VALIDATE_INT);
    if ($value === false || $value < 0 || $value > 2147483647) {
        return null;
    }

    return $value;
}

function saveZone(object $zone): void
{
    $zoneName = normalizeZoneName(rtrim((string) $zone->getName(), '.'));
    if ($zoneName === null) {
        throw new RuntimeException('Invalid zone name.');
    }

    $zoneDirectory = rtrim((string) ($_ENV['BIND9_ZONE_DIR'] ?? ''), '/');
    if ($zoneDirectory === '' || !is_dir($zoneDirectory) || !is_writable($zoneDirectory)) {
        throw new RuntimeException('The configured zone directory is not writable.');
    }

    $temporaryFile = tempnam($zoneDirectory, '.bind9-api-');
    if ($temporaryFile === false) {
        throw new RuntimeException('Unable to create a temporary zone file.');
    }

    try {
        $contents = (new AlignedBuilder())->build($zone);
        if (file_put_contents($temporaryFile, $contents, LOCK_EX) === false) {
            throw new RuntimeException('Unable to write the temporary zone file.');
        }
        if (!chmod($temporaryFile, 0640)) {
            throw new RuntimeException('Unable to set zone file permissions.');
        }

        if (envBoolean('BIND9_VALIDATE', true)) {
            [$status, $output, $error] = runCommand([
                configuredExecutable('NAMED_CHECKZONE_BIN', '/usr/sbin/named-checkzone'),
                $zoneName,
                $temporaryFile,
            ]);
            if ($status !== 0) {
                $details = trim($error !== '' ? $error : $output);
                throw new RuntimeException('named-checkzone rejected the zone: ' . $details);
            }
        }

        $zoneFile = $zoneDirectory . '/' . $zoneName . '.zone';
        if (!rename($temporaryFile, $zoneFile)) {
            throw new RuntimeException('Unable to replace the zone file.');
        }
        $temporaryFile = '';
    } finally {
        if ($temporaryFile !== '' && file_exists($temporaryFile)) {
            unlink($temporaryFile);
        }
    }
}

function backupConfigFile(string $configFile): string
{
    if (!is_file($configFile) || !is_readable($configFile)) {
        throw new RuntimeException('The configured BIND include file is not readable.');
    }

    $backupDirectory = rtrim((string) ($_ENV['BACKUP_DIR'] ?? '/var/lib/bind9-api/backups'), '/');
    if (!is_dir($backupDirectory) && !mkdir($backupDirectory, 0750, true) && !is_dir($backupDirectory)) {
        throw new RuntimeException('Unable to create the BIND backup directory.');
    }
    if (!is_writable($backupDirectory)) {
        throw new RuntimeException('The BIND backup directory is not writable.');
    }

    $backupFile = sprintf(
        '%s/%s.%s.%d.%s.bak',
        $backupDirectory,
        basename($configFile),
        gmdate('YmdHis'),
        getmypid(),
        bin2hex(random_bytes(3))
    );
    if (!copy($configFile, $backupFile)) {
        throw new RuntimeException('Unable to create a BIND configuration backup.');
    }

    return $backupFile;
}

/** @param callable(string): string $mutation */
function updateConfigFile(callable $mutation): void
{
    $configFile = (string) ($_ENV['BIND9_CONF_FILE'] ?? '');
    $handle = @fopen($configFile, 'r+');
    if ($handle === false || !flock($handle, LOCK_EX)) {
        throw new RuntimeException('Unable to lock the BIND include file.');
    }

    try {
        rewind($handle);
        $original = stream_get_contents($handle);
        if ($original === false) {
            throw new RuntimeException('Unable to read the BIND include file.');
        }

        $updated = $mutation($original);
        backupConfigFile($configFile);
        try {
            writeLockedFile($handle, $updated);
            validateBIND9Config();
        } catch (Throwable $exception) {
            try {
                writeLockedFile($handle, $original);
            } catch (Throwable $rollbackException) {
                throw new RuntimeException(
                    'The BIND include update failed and automatic rollback also failed; restore the latest backup.',
                    0,
                    $rollbackException
                );
            }
            throw $exception;
        }
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

/** @param resource $handle */
function writeLockedFile($handle, string $contents): void
{
    rewind($handle);
    if (!ftruncate($handle, 0)) {
        throw new RuntimeException('Unable to update the BIND include file.');
    }

    $length = strlen($contents);
    $written = 0;
    while ($written < $length) {
        $result = fwrite($handle, substr($contents, $written));
        if ($result === false || $result === 0) {
            throw new RuntimeException('Unable to update the BIND include file.');
        }
        $written += $result;
    }
    if (!fflush($handle)) {
        throw new RuntimeException('Unable to flush the BIND include file.');
    }
}

function zoneBlockPattern(string $zoneName): string
{
    return '/zone\s+"' . preg_quote($zoneName, '/') . '"\s*\{(?:[^{}]|\{[^{}]*\})*\};\s*/i';
}

function removeZoneFromConfig(string $zoneName): void
{
    removeTypedZoneFromConfig($zoneName, 'master');
}

function removeSlaveZoneFromConfig(string $zoneName): void
{
    removeTypedZoneFromConfig($zoneName, 'slave');
}

function removeTypedZoneFromConfig(string $zoneName, string $expectedType): void
{
    updateConfigFile(static function (string $contents) use ($zoneName, $expectedType): string {
        $pattern = zoneBlockPattern($zoneName);
        if (!preg_match($pattern, $contents, $match)) {
            throw new RuntimeException("Zone block for '{$zoneName}' was not found.");
        }
        if (!preg_match('/\btype\s+' . preg_quote($expectedType, '/') . '\s*;/i', $match[0])) {
            throw new RuntimeException("Zone '{$zoneName}' is not configured as {$expectedType}.");
        }

        $updated = preg_replace($pattern, '', $contents, 1);
        if ($updated === null) {
            throw new RuntimeException('Unable to remove the zone block.');
        }

        return $updated;
    });
}

function addZoneToConfig(string $zoneName, string $zoneFilePath): void
{
    if (preg_match('/["\r\n\x00]/', $zoneFilePath)) {
        throw new RuntimeException('The configured zone path contains invalid characters.');
    }

    updateConfigFile(static function (string $contents) use ($zoneName, $zoneFilePath): string {
        if (preg_match(zoneBlockPattern($zoneName), $contents)) {
            throw new RuntimeException("Zone '{$zoneName}' is already configured.");
        }

        return rtrim($contents) . "\n\nzone \"{$zoneName}\" {\n    type master;\n    file \"{$zoneFilePath}\";\n};\n";
    });
}

function addSlaveZoneToConfig(string $zoneName, string $masterIp): void
{
    if (filter_var($masterIp, FILTER_VALIDATE_IP) === false) {
        throw new RuntimeException('The master IP address is invalid.');
    }

    $slaveDirectory = rtrim((string) ($_ENV['BIND9_SLAVE_DIR'] ?? '/var/cache/bind'), '/');
    if (preg_match('/["\r\n\x00]/', $slaveDirectory)) {
        throw new RuntimeException('The configured slave directory contains invalid characters.');
    }

    updateConfigFile(static function (string $contents) use ($zoneName, $masterIp, $slaveDirectory): string {
        if (preg_match(zoneBlockPattern($zoneName), $contents)) {
            throw new RuntimeException("Zone '{$zoneName}' is already configured.");
        }

        return rtrim($contents) . "\n\nzone \"{$zoneName}\" {\n    type slave;\n    masters { {$masterIp}; };\n    file \"{$slaveDirectory}/{$zoneName}.zone\";\n};\n";
    });
}

/** @return list<string> */
function getConfiguredZonesByType(string $type): array
{
    $configFile = (string) ($_ENV['BIND9_CONF_FILE'] ?? '');
    $contents = @file_get_contents($configFile);
    if ($contents === false) {
        throw new RuntimeException('Unable to read the BIND include file.');
    }

    preg_match_all('/zone\s+"([^"]+)"\s*\{(?:[^{}]|\{[^{}]*\})*\};/i', $contents, $blocks, PREG_SET_ORDER);
    $zones = [];
    foreach ($blocks as $block) {
        if (preg_match('/\btype\s+' . preg_quote($type, '/') . '\s*;/i', $block[0])) {
            $zones[] = $block[1];
        }
    }

    sort($zones, SORT_NATURAL | SORT_FLAG_CASE);
    return $zones;
}

function loadZone(string $zoneName): object
{
    $zoneName = normalizeZoneName($zoneName);
    if ($zoneName === null) {
        throw new RuntimeException('Invalid zone name.');
    }

    $zoneFile = rtrim((string) ($_ENV['BIND9_ZONE_DIR'] ?? ''), '/') . '/' . $zoneName . '.zone';
    $contents = @file_get_contents($zoneFile);
    if ($contents === false) {
        throw new RuntimeException('Zone file not found.');
    }

    return Badcow\DNS\Parser\Parser::parse($zoneName . '.', $contents);
}

function validateBIND9Config(): void
{
    if (!envBoolean('BIND9_VALIDATE', true)) {
        return;
    }

    $mainConfig = (string) ($_ENV['BIND9_MAIN_CONF'] ?? '/etc/bind/named.conf');
    [$status, $output, $error] = runCommand([
        configuredExecutable('NAMED_CHECKCONF_BIN', '/usr/sbin/named-checkconf'),
        $mainConfig,
    ]);
    if ($status !== 0) {
        $details = trim($error !== '' ? $error : $output);
        throw new RuntimeException('named-checkconf rejected the configuration: ' . $details);
    }
}

function reloadBIND9(): void
{
    $rndc = configuredExecutable('RNDC_BIN', '/usr/sbin/rndc');
    [$status, $output, $error] = runCommand([$rndc, 'reload']);
    if ($status !== 0) {
        throw new RuntimeException(trim($error !== '' ? $error : $output));
    }
}

function configuredExecutable(string $key, string $default): string
{
    $path = (string) ($_ENV[$key] ?? $default);
    if (!str_starts_with($path, '/') || !is_executable($path)) {
        throw new RuntimeException($key . ' must point to an executable absolute path.');
    }

    return $path;
}

/** @param list<string> $command @return array{int, string, string} */
function runCommand(array $command): array
{
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($command, $descriptors, $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to start the BIND utility.');
    }

    fclose($pipes[0]);
    $stdout = (string) stream_get_contents($pipes[1]);
    $stderr = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return [proc_close($process), $stdout, $stderr];
}

/** @return array{user_id: int|string, username: string}|false */
function authenticate(object $request, object $pdo, LoggerInterface $log, string $clientIp): array|false
{
    $authorization = (string) ($request->header['authorization'] ?? '');
    if (!preg_match('/^Bearer\s+([a-f0-9]{64})$/i', $authorization, $match)) {
        return false;
    }

    try {
        $statement = $pdo->prepare(
            'SELECT s.user_id, u.username, s.expires_at, s.ip_address
             FROM sessions s
             JOIN users u ON s.user_id = u.id
             WHERE s.token = :token
             LIMIT 1'
        );
        $statement->execute(['token' => hash('sha256', $match[1])]);
        $session = $statement->fetch(PDO::FETCH_ASSOC);

        if (!$session || strtotime((string) $session['expires_at'] . ' UTC') < time()) {
            return false;
        }
        if (envBoolean('SESSION_BIND_IP', true) && !hash_equals((string) $session['ip_address'], $clientIp)) {
            return false;
        }

        return ['user_id' => $session['user_id'], 'username' => (string) $session['username']];
    } catch (Throwable $exception) {
        $log->error('Authentication database error', ['exception' => $exception]);
        return false;
    }
}

function generateInitialSerialNumber(): string
{
    return gmdate('Ymd') . '01';
}

function getCurrentSerialNumber(object $pdo, string $domainName): string|false
{
    $statement = $pdo->prepare('SELECT current_soa FROM zones WHERE domain_name = :domain_name');
    $statement->execute(['domain_name' => $domainName]);
    $serial = $statement->fetchColumn();
    return $serial === false ? false : (string) $serial;
}

function insertInitialSerialNumber(object $pdo, string $domainName): string
{
    $serialNumber = generateInitialSerialNumber();
    $statement = $pdo->prepare('INSERT INTO zones (domain_name, current_soa) VALUES (:domain_name, :serial_number)');
    $statement->execute(['domain_name' => $domainName, 'serial_number' => $serialNumber]);
    return $serialNumber;
}

function updateSerialNumber(object $pdo, string $domainName): string
{
    $currentSerial = getCurrentSerialNumber($pdo, $domainName);
    $serial = nextSerialNumber($currentSerial === false ? null : $currentSerial);
    $statement = $pdo->prepare(
        'UPDATE zones SET current_soa = :serial_number, updated_at = :updated_at WHERE domain_name = :domain_name'
    );
    $statement->execute([
        'serial_number' => $serial,
        'updated_at' => gmdate('Y-m-d H:i:s'),
        'domain_name' => $domainName,
    ]);
    return $serial;
}

function nextSerialNumber(?string $currentSerial): string
{
    $todayBase = (int) (gmdate('Ymd') . '01');
    if ($currentSerial === null || !preg_match('/^\d{1,10}$/', $currentSerial)) {
        return (string) $todayBase;
    }

    $current = (int) $currentSerial;
    if ($current < $todayBase) {
        return (string) $todayBase;
    }
    if ($current >= 4294967295) {
        throw new RuntimeException('The SOA serial has reached the 32-bit limit.');
    }

    return (string) ($current + 1);
}

function updateZoneSoa(object $zone, string $zoneName, object $pdo): void
{
    $newSerial = nextSerialNumber(serialNumberFromZone($zone));
    $found = false;
    foreach ($zone->getResourceRecords() as $record) {
        if (strtoupper((string) $record->getType()) === 'SOA') {
            $soa = $record->getRdata();
            $soa->setSerial($newSerial);
            $record->setRdata($soa);
            $found = true;
            break;
        }
    }
    if (!$found) {
        throw new RuntimeException('The zone has no SOA record.');
    }

    saveZone($zone);
    $statement = $pdo->prepare(
        'UPDATE zones SET current_soa = :serial_number, updated_at = :updated_at WHERE domain_name = :domain_name'
    );
    $statement->execute([
        'serial_number' => $newSerial,
        'updated_at' => gmdate('Y-m-d H:i:s'),
        'domain_name' => $zoneName,
    ]);
}

function serialNumberFromZone(object $zone): ?string
{
    foreach ($zone->getResourceRecords() as $record) {
        if (strtoupper((string) $record->getType()) === 'SOA') {
            return (string) $record->getRdata()->getSerial();
        }
    }

    return null;
}

/** @return array{preference: int, exchange: string} */
function normalizeMxRdata(mixed $rdata): array
{
    if (is_string($rdata) && preg_match('/^(\d{1,5})\s+(.+)$/', trim($rdata), $match)) {
        $rdata = ['preference' => $match[1], 'exchange' => $match[2]];
    } elseif (is_string($rdata) && trim($rdata) !== '') {
        $rdata = ['preference' => 10, 'exchange' => trim($rdata)];
    }
    if (!is_array($rdata)) {
        throw new InvalidArgumentException('MX RDATA must contain preference and exchange.');
    }

    $preference = filter_var($rdata['preference'] ?? null, FILTER_VALIDATE_INT);
    $exchange = normalizeDnsTarget($rdata['exchange'] ?? null, true);
    if ($preference === false || $preference < 0 || $preference > 65535 || $exchange === null) {
        throw new InvalidArgumentException('Invalid MX RDATA.');
    }

    return ['preference' => $preference, 'exchange' => $exchange];
}

/** @return array{keytag: int, algorithm: int, digestType: int, digest: string} */
function normalizeDsRdata(mixed $rdata): array
{
    if (is_string($rdata) && preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+([a-f0-9]+)$/i', trim($rdata), $match)) {
        $rdata = [
            'keytag' => $match[1],
            'algorithm' => $match[2],
            'digestType' => $match[3],
            'digest' => $match[4],
        ];
    }
    if (!is_array($rdata)) {
        throw new InvalidArgumentException('DS RDATA must be an object.');
    }

    $keyTag = filter_var($rdata['keytag'] ?? null, FILTER_VALIDATE_INT);
    $algorithm = filter_var($rdata['algorithm'] ?? null, FILTER_VALIDATE_INT);
    $digestType = filter_var($rdata['digestType'] ?? null, FILTER_VALIDATE_INT);
    $digest = strtoupper(trim((string) ($rdata['digest'] ?? '')));
    if (
        $keyTag === false || $keyTag < 0 || $keyTag > 65535
        || $algorithm === false || $algorithm < 0 || $algorithm > 255
        || $digestType === false || $digestType < 0 || $digestType > 255
        || $digest === '' || strlen($digest) % 2 !== 0 || !ctype_xdigit($digest)
    ) {
        throw new InvalidArgumentException('Invalid DS RDATA.');
    }

    return ['keytag' => $keyTag, 'algorithm' => $algorithm, 'digestType' => $digestType, 'digest' => $digest];
}

function normalizeDnsTarget(mixed $target, bool $absolute = false): ?string
{
    if (!is_string($target)) {
        return null;
    }

    $target = trim($target);
    $hadTrailingDot = str_ends_with($target, '.');
    $plain = rtrim($target, '.');
    if ($plain === '' || strlen($plain) > 253) {
        return null;
    }
    foreach (explode('.', $plain) as $label) {
        if (strlen($label) > 63 || !preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/', $label)) {
            return null;
        }
    }

    return $plain . (($absolute || $hadTrailingDot) ? '.' : '');
}

function normalizeTextRdata(mixed $rdata): string
{
    if (is_array($rdata)) {
        $rdata = implode(' ', array_map('strval', $rdata));
    }
    if (!is_string($rdata)) {
        throw new InvalidArgumentException('Text RDATA must be a string.');
    }

    $rdata = trim($rdata);
    if (strlen($rdata) >= 2 && (($rdata[0] === '"' && str_ends_with($rdata, '"')) || ($rdata[0] === "'" && str_ends_with($rdata, "'")))) {
        $rdata = substr($rdata, 1, -1);
    }
    if ($rdata === '' || strlen($rdata) > 65535 || preg_match('/[\x00\r\n]/', $rdata)) {
        throw new InvalidArgumentException('Invalid text RDATA.');
    }

    return $rdata;
}

function comparableTextRdata(mixed $rdata): string
{
    return normalizeTextRdata($rdata);
}

/** @return array{mname: string, rname: string, serial: int, refresh: int, retry: int, expire: int, minimum: int} */
function normalizeSoaRdata(mixed $rdata): array
{
    if (is_string($rdata)) {
        $parts = preg_split('/\s+/', trim($rdata));
        if (count($parts) === 7) {
            $rdata = array_combine(
                ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum'],
                $parts
            );
        }
    }
    if (!is_array($rdata)) {
        throw new InvalidArgumentException('SOA RDATA must be an object.');
    }

    $mname = normalizeDnsTarget($rdata['mname'] ?? null, true);
    $rname = normalizeDnsTarget($rdata['rname'] ?? null, true);
    $serial = filter_var($rdata['serial'] ?? null, FILTER_VALIDATE_INT);
    $refresh = normalizeTtl($rdata['refresh'] ?? null);
    $retry = normalizeTtl($rdata['retry'] ?? null);
    $expire = normalizeTtl($rdata['expire'] ?? null);
    $minimum = normalizeTtl($rdata['minimum'] ?? null);
    if (
        $mname === null || $rname === null || $serial === false || $serial < 0 || $serial > 4294967295
        || in_array(null, [$refresh, $retry, $expire, $minimum], true)
    ) {
        throw new InvalidArgumentException('Invalid SOA RDATA.');
    }

    return compact('mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum');
}

function buildRdata(string $type, mixed $rdata): object
{
    try {
        return match (strtoupper($type)) {
            'A' => filter_var($rdata, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
                ? Factory::A((string) $rdata)
                : throw new InvalidArgumentException('Invalid IPv4 address.'),
            'AAAA' => filter_var($rdata, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
                ? Factory::AAAA((string) $rdata)
                : throw new InvalidArgumentException('Invalid IPv6 address.'),
            'CNAME' => Factory::CNAME(normalizeDnsTarget($rdata) ?? throw new InvalidArgumentException('Invalid CNAME target.')),
            'NS' => Factory::NS(normalizeDnsTarget($rdata) ?? throw new InvalidArgumentException('Invalid NS target.')),
            'PTR' => Factory::PTR(normalizeDnsTarget($rdata) ?? throw new InvalidArgumentException('Invalid PTR target.')),
            'MX' => (static function () use ($rdata): object {
                $mx = normalizeMxRdata($rdata);
                return Factory::MX($mx['preference'], $mx['exchange']);
            })(),
            'TXT' => is_string($rdata) && str_starts_with(ltrim($rdata), '"')
                ? Factory::textToRdataType('TXT', trim($rdata))
                : Factory::TXT(normalizeTextRdata($rdata)),
            'SPF' => is_string($rdata) && str_starts_with(ltrim($rdata), '"')
                ? Factory::textToRdataType('SPF', trim($rdata))
                : Factory::SPF(normalizeTextRdata($rdata)),
            'SOA' => (static function () use ($rdata): object {
                $soa = normalizeSoaRdata($rdata);
                return Factory::SOA(
                    $soa['mname'],
                    $soa['rname'],
                    $soa['serial'],
                    $soa['refresh'],
                    $soa['retry'],
                    $soa['expire'],
                    $soa['minimum']
                );
            })(),
            'DS' => (static function () use ($rdata): object {
                $ds = normalizeDsRdata($rdata);
                $digest = hex2bin($ds['digest']);
                if ($digest === false) {
                    throw new InvalidArgumentException('Invalid DS digest.');
                }
                return Factory::DS($ds['keytag'], $ds['algorithm'], $digest, $ds['digestType']);
            })(),
            default => throw new InvalidArgumentException('Unsupported record type.'),
        };
    } catch (InvalidArgumentException $exception) {
        throw $exception;
    } catch (Throwable $exception) {
        throw new InvalidArgumentException('Invalid RDATA.', 0, $exception);
    }
}

function rdataEquivalent(string $type, object $existing, object $candidate): bool
{
    if (in_array(strtoupper($type), ['TXT', 'SPF'], true)) {
        return comparableTextRdata($existing->toText()) === comparableTextRdata($candidate->toText());
    }

    return strtolower(trim((string) $existing->toText())) === strtolower(trim((string) $candidate->toText()));
}
