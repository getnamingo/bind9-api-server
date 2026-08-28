<?php

declare(strict_types=1);

if (!extension_loaded('swoole')) {
    fwrite(STDERR, "The Swoole extension must be installed.\n");
    exit(1);
}

require_once __DIR__ . '/helpers.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Namingo\Bind9Api\Database;
use Namingo\Rately\Rately;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$logFilePath = (string) ($_ENV['LOG_FILE'] ?? '/var/log/plexdns/bind9-api.log');
$log = setupLogger($logFilePath, 'BIND9_API');

$database = new Database($_ENV);
$database->initialize();
$pool = $database->createPool();

// Handler Functions

function handleLogin(Request $request, object $pdo, string $clientIp): array
{
    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }
    $username = trim((string) ($body['username'] ?? ''));
    $password = (string) ($body['password'] ?? '');

    if (
        !preg_match('/^[A-Za-z0-9_.@-]{3,50}$/', $username)
        || $password === ''
        || strlen($password) > 1024
    ) {
        return [400, ['error' => 'Username and password are required']];
    }

    try {
        $stmt = $pdo->prepare('SELECT id, username, password FROM users WHERE username = :username LIMIT 1');
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (
            !$user
            || !hash_equals((string) $user['username'], $username)
            || !password_verify($password, (string) $user['password'])
        ) {
            return [401, ['error' => 'Invalid credentials']];
        }

        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $createdAt = gmdate('Y-m-d H:i:s');
        $expiresAt = gmdate('Y-m-d H:i:s', time() + envInteger('SESSION_TTL', 3600, 300, 86400));

        $stmt = $pdo->prepare('
            INSERT INTO sessions (user_id, token, ip_address, user_agent, created_at, expires_at)
            VALUES (:user_id, :token, :ip_address, :user_agent, :created_at, :expires_at)
        ');

        $userAgent = substr((string) ($request->header['user-agent'] ?? ''), 0, 255);

        $stmt->execute([
            'user_id' => $user['id'],
            'token' => $tokenHash,
            'ip_address' => $clientIp,
            'user_agent' => $userAgent,
            'created_at' => $createdAt,
            'expires_at' => $expiresAt,
        ]);

        return [200, ['token' => $token]];
    } catch (Throwable $e) {
        error_log('Login error: ' . $e->getMessage());
        return [500, ['error' => 'Internal server error']];
    }
}

function handleGetZones(): array
{
    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $files = glob("$zoneDir/*.zone") ?: [];
    $zones = array_map(static function (string $file): string {
        return basename($file, '.zone');
    }, $files);
    sort($zones, SORT_NATURAL | SORT_FLAG_CASE);
    return [200, ['zones' => $zones]];
}

function handleGetSlaveZones(): array
{
    try {
        return [200, ['zones' => getConfiguredZonesByType('slave')]];
    } catch (Throwable $exception) {
        return [500, ['error' => publicError('Unable to read BIND9 configuration', $exception)]];
    }
}

/**
 * Handle adding a new zone.
 * Accepts optional SOA and NS parameters in the request body.
 */
function handleAddZone(Request $request, object $pdo): array
{
    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }
    $zoneName = normalizeZoneName($body['zone'] ?? null);
    if ($zoneName === null) {
        return [400, ['error' => 'Invalid zone name format']];
    }

    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $zoneFile = "$zoneDir/$zoneName.zone";

    if (file_exists($zoneFile)) {
        return [409, ['error' => 'Zone already exists']];
    }

    try {
        $zone = new Zone($zoneName.'.');
        
        $serialNumber = getCurrentSerialNumber($pdo, $zoneName);
        if (!$serialNumber) {
            $serialNumber = insertInitialSerialNumber($pdo, $zoneName);
        } else {
            $serialNumber = updateSerialNumber($pdo, $zoneName);
        }
        
        $soa_ns = normalizeDnsTarget($body['soa_ns'] ?? ($_ENV['NS1'] ?? null), true);
        $soa_email = normalizeDnsTarget($body['soa_email'] ?? ($_ENV['SOA_EMAIL'] ?? null), true);
        $refresh = normalizeTtl($body['refresh'] ?? ($_ENV['REFRESH'] ?? null));
        $retry = normalizeTtl($body['retry'] ?? ($_ENV['RETRY'] ?? null));
        $expire = normalizeTtl($body['expire'] ?? ($_ENV['EXPIRE'] ?? null));
        $min_ttl = normalizeTtl($body['min_ttl'] ?? ($_ENV['MIN_TTL'] ?? null));
        if ($soa_ns === null || $soa_email === null || in_array(null, [$refresh, $retry, $expire, $min_ttl], true)) {
            return [400, ['error' => 'Invalid SOA parameters']];
        }

        // Add default SOA record
        $soa = new ResourceRecord;
        $soa->setName('@');
        $soa->setClass(Classes::INTERNET);
        $soa->setRdata(Factory::Soa(
            $soa_ns,
            $soa_email,
            $serialNumber,
            $refresh,
            $retry,
            $expire,
            $min_ttl
        ));
        $zone->addResourceRecord($soa);

        // Add NS records; check for override in request body, fallback to .env.
        for ($i = 1; $i <= 13; $i++) {
            $nsKey = 'NS' . $i;
            if (isset($body[$nsKey])) {
                $nsValue = $body[$nsKey];
            } elseif (isset($_ENV[$nsKey])) {
                $nsValue = $_ENV[$nsKey];
            } else {
                continue;
            }
            if (!empty($nsValue)) {
                $nsValue = normalizeDnsTarget($nsValue, true);
                if ($nsValue === null) {
                    return [400, ['error' => "Invalid {$nsKey} value"]];
                }
                $nsRecord = new ResourceRecord;
                $nsRecord->setName('@');
                $nsRecord->setClass(Classes::INTERNET);
                $nsRecord->setRdata(Factory::Ns($nsValue));
                $zone->addResourceRecord($nsRecord);
            }
        }

        saveZone($zone);
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to create zone file', $e)]];
    }

    try {
        addZoneToConfig($zoneName, $zoneFile);
    } catch (Throwable $e) {
        @unlink($zoneFile);
        return [500, ['error' => publicError('Failed to update BIND configuration', $e)]];
    }

    try {
        reloadBIND9();
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to reload BIND9', $e)]];
    }

    return [201, ['message' => 'Zone created successfully']];
}

/**
 * Handle adding a slave zone.
 * Requires the master server IP in the request body.
 */
function handleAddSlaveZone(Request $request): array
{
    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }

    $zoneName = normalizeZoneName($body['zone'] ?? null);
    $masterIp = normalizeIpAddress($body['master_ip'] ?? null);

    if ($zoneName === null) {
        return [400, ['error' => 'Invalid zone name format']];
    }

    if ($masterIp === null) {
        return [400, ['error' => 'Valid master IP is required']];
    }

    try {
        addSlaveZoneToConfig($zoneName, $masterIp);
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to update BIND configuration', $e)]];
    }

    try {
        reloadBIND9();
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to reload BIND9', $e)]];
    }

    return [201, ['message' => 'Slave zone added successfully']];
}

/**
 * Handle deleting an existing zone.
 */
function handleDeleteZone(string $zoneName): array
{
    $zoneName = normalizeZoneName($zoneName);
    if ($zoneName === null) {
        return [400, ['error' => 'Invalid zone name format']];
    }

    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $zoneFile = "$zoneDir/$zoneName.zone";

    if (!file_exists($zoneFile)) {
        return [404, ['error' => 'Zone file does not exist']];
    }

    try {
        removeZoneFromConfig($zoneName);
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to update BIND configuration', $e)]];
    }

    if (!unlink($zoneFile)) {
        return [500, ['error' => 'Failed to delete zone file']];
    }

    try {
        reloadBIND9();
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to reload BIND9', $e)]];
    }

    return [200, ['message' => 'Zone deleted successfully']];
}

/**
 * Handle deleting a slave zone.
 */
function handleDeleteSlaveZone(string $zoneName): array
{
    $zoneName = normalizeZoneName($zoneName);
    if ($zoneName === null) {
        return [400, ['error' => 'Invalid zone name format']];
    }

    try {
        removeSlaveZoneFromConfig($zoneName);
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to update BIND configuration', $e)]];
    }

    try {
        reloadBIND9();
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to reload BIND9', $e)]];
    }

    return [200, ['message' => 'Slave zone deleted successfully']];
}

function handleGetRecords(string $zoneName): array
{
    $zoneName = normalizeZoneName($zoneName);
    if ($zoneName === null) {
        return [400, ['error' => 'Invalid or empty zone name']];
    }

    try {
        $zone = loadZone($zoneName);
    } catch (Throwable $e) {
        return [404, ['error' => publicError('Zone not found', $e)]];
    }

    $records = [];
    foreach ($zone->getResourceRecords() as $record) {
        $records[] = [
            'name' => $record->getName(),
            'type' => $record->getType(),
            'ttl' => $record->getTtl(),
            'rdata' => $record->getRdata()->toText()
        ];
    }

    return [200, ['records' => $records]];
}

/**
 * Handle adding a new DNS record.
 * Now receives $pdo to allow updating the SOA record.
 */
function handleAddRecord(string $zoneName, Request $request, object $pdo): array
{
    $zoneName = normalizeZoneName($zoneName);
    if ($zoneName === null) {
        return [400, ['error' => 'Invalid or empty zone name']];
    }

    try {
        $zone = loadZone($zoneName);
    } catch (Throwable $e) {
        return [404, ['error' => publicError('Zone not found', $e)]];
    }

    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }
    $name = isset($body['name']) ? trim((string) $body['name']) : '@';
    $type = strtoupper(trim((string) ($body['type'] ?? '')));
    $ttl = normalizeTtl($body['ttl'] ?? 3600);
    $hasRdata = array_key_exists('rdata', $body);
    $rdata = $body['rdata'] ?? null;

    if ($name === '') {
        $name = '@';
    }

    if (!isValidRecordName($name)) {
        return [400, ['error' => 'Invalid record name']];
    }
    if ($type === '' || !$hasRdata || $ttl === null) {
        return [400, ['error' => 'Missing required fields']];
    }

    try {
        $rdataInstance = buildRdata($type, $rdata);
    } catch (InvalidArgumentException $exception) {
        return [400, ['error' => $exception->getMessage()]];
    }

    foreach ($zone->getResourceRecords() as $existingRecord) {
        if ($type === 'SOA' && strtoupper((string) $existingRecord->getType()) === 'SOA') {
            return [409, ['error' => 'The zone already has an SOA record']];
        }
        if (
            strcasecmp((string) $existingRecord->getName(), $name) === 0
            && strtoupper((string) $existingRecord->getType()) === $type
            && rdataEquivalent($type, $existingRecord->getRdata(), $rdataInstance)
        ) {
            return [409, ['error' => 'Record already exists']];
        }
    }

    $record = new ResourceRecord;
    $record->setName($name);
    $record->setTtl($ttl);
    $record->setClass(Classes::INTERNET);
    $record->setRdata($rdataInstance);

    $zone->addResourceRecord($record);

    try {
        updateZoneSoa($zone, $zoneName, $pdo);
    } catch (Throwable $exception) {
        return [500, ['error' => publicError('Failed to save zone', $exception)]];
    }

    try {
        reloadBIND9();
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to reload BIND9', $e)]];
    }

    return [201, ['message' => 'Record added successfully']];
}

/**
 * Handle updating an existing DNS record.
 * Now receives $pdo to update the SOA record.
 */
function handleUpdateRecord(string $zoneName, Request $request, object $pdo): array
{
    $zoneName = normalizeZoneName($zoneName);
    if ($zoneName === null) {
        return [400, ['error' => 'Invalid or empty zone name']];
    }

    try {
        $zone = loadZone($zoneName);
    } catch (Throwable $e) {
        return [404, ['error' => publicError('Zone not found', $e)]];
    }

    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }

    $currentName = trim((string) ($body['current_name'] ?? ''));
    $currentType = strtoupper(trim((string) ($body['current_type'] ?? '')));
    $hasCurrentRdata = array_key_exists('current_rdata', $body);
    $currentRdataRaw = $body['current_rdata'] ?? null;
    $currentRdata = is_string($currentRdataRaw) ? trim($currentRdataRaw) : $currentRdataRaw;

    $newName = trim((string) ($body['new_name'] ?? $currentName));
    $newTtl = array_key_exists('new_ttl', $body) ? normalizeTtl($body['new_ttl']) : null;

    $newRdataRaw = $body['new_rdata'] ?? $currentRdata;
    $newRdata    = is_string($newRdataRaw) ? trim($newRdataRaw) : $newRdataRaw;
    $newComment = array_key_exists('new_comment', $body) ? trim((string) $body['new_comment']) : null;

    if ($currentName === '' || $currentType === '' || !$hasCurrentRdata) {
        return [400, ['error' => 'Current record name, type, and rdata are required for identification']];
    }
    if (strcasecmp(rtrim($currentName, '.'), $zoneName) === 0) {
        $currentName = '@';
    }
    if (strcasecmp(rtrim($newName, '.'), $zoneName) === 0) {
        $newName = '@';
    }
    if (!isValidRecordName($currentName) || !isValidRecordName($newName)) {
        return [400, ['error' => 'Invalid record name']];
    }
    if (array_key_exists('new_ttl', $body) && $newTtl === null) {
        return [400, ['error' => 'Invalid TTL']];
    }
    if ($newComment !== null && preg_match('/[\x00\r\n]/', $newComment)) {
        return [400, ['error' => 'Invalid comment']];
    }
    try {
        $currentRdataInstance = buildRdata($currentType, $currentRdata);
        $newRdataInstance = buildRdata($currentType, $newRdata);
    } catch (InvalidArgumentException $exception) {
        return [400, ['error' => $exception->getMessage()]];
    }

    $recordToUpdate = null;
    foreach ($zone->getResourceRecords() as $record) {
        if (
            strcasecmp((string) $record->getName(), $currentName) === 0
            && strtoupper((string) $record->getType()) === $currentType
            && rdataEquivalent($currentType, $record->getRdata(), $currentRdataInstance)
        ) {
            $recordToUpdate = $record;
            break;
        }
    }

    if (!$recordToUpdate) {
        return [404, ['error' => 'Record not found']];
    }

    if ($newName) {
        $recordToUpdate->setName($newName);
    }
    if ($newTtl !== null) {
        $recordToUpdate->setTtl($newTtl);
    }
    $recordToUpdate->setRdata($newRdataInstance);
    if ($newComment !== null) {
        $recordToUpdate->setComment($newComment);
    }

    try {
        updateZoneSoa($zone, $zoneName, $pdo);
    } catch (Throwable $exception) {
        return [500, ['error' => publicError('Failed to save zone', $exception)]];
    }

    try {
        reloadBIND9();
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to reload BIND9', $e)]];
    }

    return [200, ['message' => 'Record updated successfully']];
}

/**
 * Handle deleting an existing DNS record.
 * Now receives $pdo to update the SOA record.
 */
function handleDeleteRecord(string $zoneName, Request $request, object $pdo): array
{
    $zoneName = normalizeZoneName($zoneName);
    if ($zoneName === null) {
        return [400, ['error' => 'Invalid or empty zone name']];
    }

    try {
        $zone = loadZone($zoneName);
    } catch (Throwable $e) {
        return [404, ['error' => publicError('Zone not found', $e)]];
    }

    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }

    $recordName = trim((string) ($body['name'] ?? ''));
    $recordType = strtoupper(trim((string) ($body['type'] ?? '')));
    if (strcasecmp(rtrim($recordName, '.'), $zoneName) === 0) {
        $recordName = '@';
    }
    $hasRdata = array_key_exists('rdata', $body);
    $recordRdata = $body['rdata'] ?? null;

    if ($recordName === '' || $recordType === '' || !$hasRdata) {
        return [400, ['error' => 'Record name, type, and rdata are required for identification']];
    }
    if ($recordType === 'SOA') {
        return [400, ['error' => 'The SOA record cannot be deleted']];
    }
    if (!isValidRecordName($recordName)) {
        return [400, ['error' => 'Invalid record name']];
    }
    try {
        $requestedRdata = buildRdata($recordType, $recordRdata);
    } catch (InvalidArgumentException $exception) {
        return [400, ['error' => $exception->getMessage()]];
    }

    $recordToDelete = null;
    foreach ($zone->getResourceRecords() as $record) {
        if (
            strcasecmp((string) $record->getName(), $recordName) === 0
            && strtoupper((string) $record->getType()) === $recordType
            && rdataEquivalent($recordType, $record->getRdata(), $requestedRdata)
        ) {
            $recordToDelete = $record;
            break;
        }
    }

    if (!$recordToDelete) {
        return [404, ['error' => 'Record not found']];
    }

    $zone->remove($recordToDelete);

    try {
        updateZoneSoa($zone, $zoneName, $pdo);
    } catch (Throwable $exception) {
        return [500, ['error' => publicError('Failed to save zone', $exception)]];
    }

    try {
        reloadBIND9();
    } catch (Throwable $e) {
        return [500, ['error' => publicError('Failed to reload BIND9', $e)]];
    }

    return [200, ['message' => 'Record deleted successfully']];
}

function respondJson(Response $response, int $status, array $body): void
{
    $response->status($status);
    $response->header('Content-Type', 'application/json; charset=utf-8');
    $response->header('Cache-Control', 'no-store');
    $response->header('X-Content-Type-Options', 'nosniff');
    $response->end(json_encode($body, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
}

$apiHost = (string) ($_ENV['API_HOST'] ?? '127.0.0.1');
if (filter_var($apiHost, FILTER_VALIDATE_IP) === false) {
    throw new RuntimeException('API_HOST must be an IPv4 or IPv6 address.');
}
$apiPort = envInteger('API_PORT', 7650, 1, 65535);
$workerNumber = envInteger('WORKER_NUM', 1, 1, 128);
$pidFile = (string) ($_ENV['PID_FILE'] ?? '/run/bind9-api/bind9-api.pid');

$socketType = filter_var($apiHost, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
    ? SWOOLE_SOCK_TCP6
    : SWOOLE_SOCK_TCP;
$server = new Server($apiHost, $apiPort, SWOOLE_PROCESS, $socketType);
$server->set([
    'daemonize' => false,
    'log_file' => $logFilePath,
    'log_level' => SWOOLE_LOG_INFO,
    'worker_num' => $workerNumber,
    'pid_file' => $pidFile,
    'max_request' => 10000,
    'dispatch_mode' => 1,
    'open_tcp_nodelay' => true,
    'max_conn' => 1024,
    'buffer_output_size' => 2 * 1024 * 1024,
    'heartbeat_check_interval' => 60,
    'heartbeat_idle_time' => 600,
    'package_max_length' => 2 * 1024 * 1024,
    'reload_async' => true,
    'http_compression' => true,
    'enable_coroutine' => true,
]);

$rateLimiter = new Rately();
$loginRateLimit = envInteger('LOGIN_RATE_LIMIT', 10, 1, 10000);
$rateLimit = envInteger('RATE_LIMIT', 120, 1, 1000000);
$ratePeriod = envInteger('RATE_PERIOD', 60, 1, 86400);

$server->on('request', function (Request $request, Response $response) use (
    $database,
    $pool,
    $log,
    $rateLimiter,
    $loginRateLimit,
    $rateLimit,
    $ratePeriod
): void {
    $pdo = null;
    $path = '/';

    try {
        $pdo = $database->acquire($pool);
        $clientIp = getClientIp($request);
        if ($clientIp === '') {
            respondJson($response, 400, ['error' => 'Unable to determine client IP address']);
            return;
        }

        $rawUri = (string) ($request->server['request_uri'] ?? '/');
        $parsedPath = parse_url($rawUri, PHP_URL_PATH);
        $path = rawurldecode(is_string($parsedPath) ? $parsedPath : '/');
        if (str_contains($path, "\0")) {
            respondJson($response, 400, ['error' => 'Invalid path']);
            return;
        }
        $method = strtoupper((string) ($request->server['request_method'] ?? 'GET'));

        $effectiveLimit = $path === '/login' ? $loginRateLimit : $rateLimit;
        $rateKey = $path === '/login' ? 'bind9_api_login' : 'bind9_api';
        if (
            !isIpWhitelisted($clientIp, $pdo)
            && envBoolean('RATELY', true)
            && $rateLimiter->isRateLimited($rateKey, $clientIp, $effectiveLimit, $ratePeriod)
        ) {
            $log->warning('Rate limit exceeded', ['client_ip' => $clientIp]);
            $response->header('Retry-After', (string) $ratePeriod);
            respondJson($response, 429, ['error' => 'Rate limit exceeded. Please try again later.']);
            return;
        }

        if ($path === '/login' && $method === 'POST') {
            [$status, $body] = handleLogin($request, $pdo, $clientIp);
            respondJson($response, $status, $body);
            return;
        }

        if (!authenticate($request, $pdo, $log, $clientIp)) {
            respondJson($response, 401, ['error' => 'Unauthorized']);
            return;
        }

        if ($path === '/zones' && in_array($method, ['GET', 'POST'], true)) {
            [$status, $body] = $method === 'GET' ? handleGetZones() : handleAddZone($request, $pdo);
            respondJson($response, $status, $body);
            return;
        }

        if ($path === '/slave-zones' && in_array($method, ['GET', 'POST'], true)) {
            [$status, $body] = $method === 'GET' ? handleGetSlaveZones() : handleAddSlaveZone($request);
            respondJson($response, $status, $body);
            return;
        }

        if (preg_match('#^/zones/([^/]+)$#', $path, $matches) && $method === 'DELETE') {
            [$status, $body] = handleDeleteZone($matches[1]);
            respondJson($response, $status, $body);
            return;
        }

        if (preg_match('#^/slave-zones/([^/]+)$#', $path, $matches) && $method === 'DELETE') {
            [$status, $body] = handleDeleteSlaveZone($matches[1]);
            respondJson($response, $status, $body);
            return;
        }

        if (preg_match('#^/zones/([^/]+)/records$#', $path, $matches) && in_array($method, ['GET', 'POST'], true)) {
            [$status, $body] = $method === 'GET'
                ? handleGetRecords($matches[1])
                : handleAddRecord($matches[1], $request, $pdo);
            respondJson($response, $status, $body);
            return;
        }

        if (preg_match('#^/zones/([^/]+)/records/(update|delete)$#', $path, $matches)) {
            if ($matches[2] === 'update' && $method === 'PUT') {
                [$status, $body] = handleUpdateRecord($matches[1], $request, $pdo);
                respondJson($response, $status, $body);
                return;
            }
            if ($matches[2] === 'delete' && $method === 'DELETE') {
                [$status, $body] = handleDeleteRecord($matches[1], $request, $pdo);
                respondJson($response, $status, $body);
                return;
            }
        }

        respondJson($response, 404, ['error' => 'Path not found']);
    } catch (PDOException $exception) {
        $log->error('Database request failure', ['exception' => $exception, 'path' => $path]);
        respondJson($response, 500, ['error' => publicError('Internal database error', $exception)]);
    } catch (Throwable $exception) {
        $log->error('Unhandled request failure', ['exception' => $exception, 'path' => $path]);
        respondJson($response, 500, ['error' => publicError('Internal server error', $exception)]);
    } finally {
        $database->release($pool, $pdo);
    }
});

// Register the cleanup timer inside worker 0. The old implementation placed it
// after Server::start(), where it could never execute.
$server->on('workerStart', function (Server $server, int $workerId) use ($database, $pool, $log): void {
    if ($workerId !== 0) {
        return;
    }

    Swoole\Timer::tick(60000, function () use ($database, $pool, $log): void {
        $pdo = null;
        try {
            $pdo = $database->acquire($pool);
            $statement = $pdo->prepare('DELETE FROM sessions WHERE expires_at < :now');
            $statement->execute(['now' => gmdate('Y-m-d H:i:s')]);
            if ($statement->rowCount() > 0) {
                $log->info('Expired sessions removed', ['count' => $statement->rowCount()]);
            }
        } catch (Throwable $exception) {
            $log->error('Failed to clean up expired sessions', ['exception' => $exception]);
        } finally {
            $database->release($pool, $pdo);
        }
    });
});

$log->info('BIND9 API server starting', [
    'listen' => ($socketType === SWOOLE_SOCK_TCP6 ? '[' . $apiHost . ']' : $apiHost) . ':' . $apiPort,
    'database' => $database->driver(),
    'workers' => $workerNumber,
]);
$server->start();
