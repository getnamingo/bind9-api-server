<?php
// Include the Swoole extension
if (!extension_loaded('swoole')) {
    die('Swoole extension must be installed');
}

require_once 'helpers.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Namingo\Rately\Rately;

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$logFilePath = '/var/log/plexdns/bind9_api.log';
$log = setupLogger($logFilePath, 'BIND9_API');

// Initialize the PDO connection pool
$pool = new Swoole\Database\PDOPool(
    (new Swoole\Database\PDOConfig())
        ->withDriver($_ENV['DB_TYPE'])
        ->withHost($_ENV['DB_HOST'])
        ->withPort($_ENV['DB_PORT'])
        ->withDbName($_ENV['DB_DATABASE'])
        ->withUsername($_ENV['DB_USERNAME'])
        ->withPassword($_ENV['DB_PASSWORD'])
        ->withCharset('utf8mb4')
);

// Handler Functions

function handleLogin($request, $pdo) {
    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }
    $username = trim($body['username'] ?? '');
    $password = $body['password'] ?? '';

    if (empty($username) || empty($password)) {
        return [400, ['error' => 'Username and password are required']];
    }

    try {
        $stmt = $pdo->prepare('SELECT id, password FROM users WHERE BINARY username = :username LIMIT 1');
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['password'])) {
            return [401, ['error' => 'Invalid credentials']];
        }

        $token = password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT);

        $stmt = $pdo->prepare('
            INSERT INTO sessions (user_id, token, ip_address, user_agent, created_at, expires_at)
            VALUES (:user_id, :token, :ip_address, :user_agent, NOW(), DATE_ADD(NOW(), INTERVAL 1 HOUR))
        ');

        $ipAddress = filter_var($request->server['remote_addr'] ?? '', FILTER_VALIDATE_IP) ?: null;
        $userAgent = substr($request->header['user-agent'] ?? '', 0, 255);

        $stmt->execute([
            'user_id' => $user['id'],
            'token' => $token,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent
        ]);

        return [200, ['token' => $token]];
    } catch (Exception $e) {
        error_log('Login error: ' . $e->getMessage());
        return [500, ['error' => 'Internal server error']];
    }
}

function handleGetZones() {
    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $files = glob("$zoneDir/*.zone");
    $zones = array_map(function($file) {
        return basename($file, '.zone');
    }, $files);
    return [200, ['zones' => $zones]];
}

function handleGetSlaveZones() {
    $configFile = $_ENV['BIND9_CONF_FILE'];
    
    $configContent = file_get_contents($configFile);
    if ($configContent === false) {
        return [500, ['error' => 'Unable to read BIND9 configuration']];
    }

    preg_match_all('/zone\s+"([^"]+)"\s*\{\s*type\s+slave;/i', $configContent, $matches);
    
    $zones = $matches[1] ?? [];

    return [200, ['zones' => $zones]];
}

/**
 * Handle adding a new zone.
 * Accepts optional SOA and NS parameters in the request body.
 */
function handleAddZone($request, $pdo) {
    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }
    $zoneName = trim($body['zone'] ?? '');

    if (!$zoneName) {
        return [400, ['error' => 'Zone name is required']];
    }
    
    if (!isValidDomainName($zoneName)) {
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
        
        // Use optional SOA parameters from request body; fallback to .env values.
        $soa_ns    = $body['soa_ns']   ?? $_ENV['NS1'];
        $soa_email = $body['soa_email'] ?? $_ENV['SOA_EMAIL'];
        $refresh   = $body['refresh']   ?? $_ENV['REFRESH'];
        $retry     = $body['retry']     ?? $_ENV['RETRY'];
        $expire    = $body['expire']    ?? $_ENV['EXPIRE'];
        $min_ttl   = $body['min_ttl']   ?? $_ENV['MIN_TTL'];

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
                $nsRecord = new ResourceRecord;
                $nsRecord->setName('@');
                $nsRecord->setClass(Classes::INTERNET);
                $nsRecord->setRdata(Factory::Ns($nsValue));
                $zone->addResourceRecord($nsRecord);
            }
        }

        saveZone($zone);
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to create zone file: ' . $e->getMessage()]];
    }

    try {
        addZoneToConfig($zoneName, $zoneFile);
    } catch (Exception $e) {
        unlink($zoneFile);
        return [500, ['error' => 'Failed to update named.conf.local: ' . $e->getMessage()]];
    }

    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [201, ['message' => 'Zone created successfully']];
}

/**
 * Handle adding a slave zone.
 * Requires the master server IP in the request body.
 */
function handleAddSlaveZone($request) {
    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }

    $zoneName = trim($body['zone'] ?? '');
    $masterIp = trim($body['master_ip'] ?? '');

    if (!$zoneName) {
        return [400, ['error' => 'Zone name is required']];
    }

    if (!isValidDomainName($zoneName)) {
        return [400, ['error' => 'Invalid zone name format']];
    }

    if (!$masterIp || !filter_var($masterIp, FILTER_VALIDATE_IP)) {
        return [400, ['error' => 'Valid master IP is required']];
    }

    try {
        addSlaveZoneToConfig($zoneName, $masterIp);
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to update named.conf.local: ' . $e->getMessage()]];
    }

    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [201, ['message' => 'Slave zone added successfully']];
}

/**
 * Handle deleting an existing zone.
 */
function handleDeleteZone($zoneName) {
    $zoneName = trim($zoneName);

    if (!$zoneName) {
        return [400, ['error' => 'Zone name is required']];
    }

    if (!isValidDomainName($zoneName)) {
        return [400, ['error' => 'Invalid zone name format']];
    }

    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $zoneFile = "$zoneDir/$zoneName.zone";

    if (!file_exists($zoneFile)) {
        return [404, ['error' => 'Zone file does not exist']];
    }

    try {
        removeZoneFromConfig($zoneName);
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to update named.conf.local: ' . $e->getMessage()]];
    }

    if (!unlink($zoneFile)) {
        return [500, ['error' => 'Failed to delete zone file']];
    }

    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [200, ['message' => 'Zone deleted successfully']];
}

/**
 * Handle deleting a slave zone.
 */
function handleDeleteSlaveZone($zoneName) {
    $zoneName = trim($zoneName);

    if (!$zoneName) {
        return [400, ['error' => 'Zone name is required']];
    }

    if (!isValidDomainName($zoneName)) {
        return [400, ['error' => 'Invalid zone name format']];
    }

    try {
        removeSlaveZoneFromConfig($zoneName);
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to update named.conf.local: ' . $e->getMessage()]];
    }

    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [200, ['message' => 'Slave zone deleted successfully']];
}

function handleGetRecords($zoneName) {
    if (empty($zoneName) || !isValidDomainName($zoneName)) {
        return [400, ['error' => 'Invalid or empty zone name']];
    }

    try {
        $zone = loadZone($zoneName);
    } catch (Exception $e) {
        return [404, ['error' => $e->getMessage()]];
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
function handleAddRecord($zoneName, $request, $pdo) {
    if (empty($zoneName) || !isValidDomainName($zoneName)) {
        return [400, ['error' => 'Invalid or empty zone name']];
    }

    try {
        $zone = loadZone($zoneName);
    } catch (Exception $e) {
        return [404, ['error' => $e->getMessage()]];
    }

    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }
    $name = isset($body['name']) ? trim($body['name']) : '@';
    $type = strtoupper($body['type'] ?? '');
    $ttl = $body['ttl'] ?? 3600;
    $rdata = $body['rdata'] ?? '';

    if ($name === '') {
        $name = '@';
    }

    if (!$type || !$rdata) {
        return [400, ['error' => 'Missing required fields']];
    }

    foreach ($zone->getResourceRecords() as $existingRecord) {
        if ($existingRecord->getName() === $name && $existingRecord->getRdata()->getType() === $type) {
            // Compare based on type (A, AAAA, CNAME, etc.)
            switch ($type) {
                case 'A':
                case 'AAAA':
                    if ($existingRecord->getRdata()->getAddress() === $rdata) {
                        return [400, ['error' => 'Record already exists']];
                    }
                    break;
                case 'CNAME':
                case 'NS':
                case 'PTR':
                    if ($existingRecord->getRdata()->getTarget() === $rdata) {
                        return [400, ['error' => 'Record already exists']];
                    }
                    break;
                case 'MX':
                    $rdata_n = normalizeMxRdata($rdata);

                    $existingMx = $existingRecord->getRdata();
                    $existingNorm = normalizeMxRdata([
                        'preference' => $existingMx->getPreference(),
                        'exchange'   => $existingMx->getExchange(),
                    ]);

                    if (
                        $existingNorm['preference'] == $rdata_n['preference'] &&
                        $existingNorm['exchange'] === $rdata_n['exchange']
                    ) {
                        return [400, ['error' => 'Record already exists']];
                    }
                    break;
                case 'SOA':
                    $soa = $existingRecord->getRdata();
                    if ($soa->getMname() === $rdata['mname'] &&
                        $soa->getRname() === $rdata['rname'] &&
                        $soa->getSerial() == $rdata['serial'] &&
                        $soa->getRefresh() == $rdata['refresh'] &&
                        $soa->getRetry() == $rdata['retry'] &&
                        $soa->getExpire() == $rdata['expire'] &&
                        $soa->getMinimum() == $rdata['minimum']) {
                        return [400, ['error' => 'Record already exists']];
                    }
                    break;
                case 'SPF':
                case 'TXT':
                    $existingTextNorm = normalizeSpfRdata($existingRecord->getRdata()->getText());
                    $newTextNorm      = normalizeSpfRdata($rdata);

                    if ($existingTextNorm === $newTextNorm) {
                        return [400, ['error' => 'Record already exists']];
                    }
                    break;
                case 'DS':
                    $ds = $existingRecord->getRdata();
                    $existingDigestHex = strtolower(bin2hex($ds->getDigest()));
                    $newDigestHex      = strtolower(is_array($rdata) ? $rdata['digest'] : $rdata);

                    if (
                        $ds->getKeyTag() == $rdata['keytag'] &&
                        $ds->getAlgorithm() == $rdata['algorithm'] &&
                        $ds->getDigestType() == $rdata['digestType'] &&
                        $existingDigestHex === $newDigestHex
                    ) {
                        return [400, ['error' => 'Record already exists']];
                    }
                    break;
                default:
                    return [400, ['error' => 'Unsupported record type']];
            }
        }
    }

    $record = new ResourceRecord;
    $record->setName($name);
    if (is_numeric($ttl)) {
        $record->setTtl($ttl);
    }
    $record->setClass(Classes::INTERNET);

    try {
        $factoryMethods = [
            'A' => 'A',
            'AAAA' => 'AAAA',
            'CNAME' => 'CNAME',
            'MX' => 'MX',
            'NS' => 'NS',
            'PTR' => 'PTR',
            'SOA' => 'SOA',
            'TXT' => 'TXT',
            'SPF' => 'SPF',
            'DS' => 'DS',
        ];
        $normalizedType = strtoupper($type);
        if (!isset($factoryMethods[$normalizedType])) {
            return [400, ['error' => 'Unsupported record type']];
        }
        $methodName = $factoryMethods[$normalizedType];
        if ($type === 'MX') {
            $mx = normalizeMxRdata($rdata);
            $rdataInstance = \Badcow\DNS\Rdata\Factory::MX($mx['preference'], $mx['exchange']);
        } else if ($type === 'DS') {
            $keytag = $rdata['keytag'];
            $algorithm = $rdata['algorithm'];
            $digestType = $rdata['digestType'];
            $digest = $rdata['digest'];
            $rdataInstance = \Badcow\DNS\Rdata\Factory::DS($keytag, $algorithm, hex2bin($digest), $digestType);
        } else {
            $rdataInstance = \Badcow\DNS\Rdata\Factory::$methodName($rdata);
        }
        $record->setRdata($rdataInstance);
    } catch (Exception $e) {
        return [400, ['error' => 'Invalid RDATA: ' . $e->getMessage()]];
    }

    $zone->addResourceRecord($record);

    // Update SOA serial to trigger sync.
    updateZoneSoa($zone, $zoneName, $pdo);

    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [201, ['message' => 'Record added successfully']];
}

/**
 * Handle updating an existing DNS record.
 * Now receives $pdo to update the SOA record.
 */
function handleUpdateRecord($zoneName, $request, $pdo) {
    try {
        $zone = loadZone($zoneName);
    } catch (Exception $e) {
        return [404, ['error' => $e->getMessage()]];
    }

    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }

    $currentName = trim($body['current_name'] ?? '');
    $currentType = strtoupper(trim($body['current_type'] ?? ''));
    $currentRdataRaw = $body['current_rdata'] ?? '';
    $currentRdata = is_string($currentRdataRaw) ? trim($currentRdataRaw) : $currentRdataRaw;

    $newName = trim($body['new_name'] ?? $currentName);
    $newTtl  = isset($body['new_ttl']) ? intval($body['new_ttl']) : 3600;

    $newRdataRaw = $body['new_rdata'] ?? $currentRdata;
    $newRdata    = is_string($newRdataRaw) ? trim($newRdataRaw) : $newRdataRaw;
    $newComment = trim($body['new_comment'] ?? '');

    if (!$currentName || !$currentType || !$currentRdata) {
        return [400, ['error' => 'Current record name, type, and rdata are required for identification']];
    }
    if ($currentType === 'MX' && rtrim($currentName, '.') === rtrim($zoneName, '.')) {
        $currentName = '@';
    }

    $currentMxNorm = null;
    if ($currentType === 'MX') {
        $currentMxNorm = normalizeMxRdata($currentRdata);
    }

    $recordToUpdate = null;
    foreach ($zone->getResourceRecords() as $record) {
        if (
            strtolower($record->getName()) === strtolower($currentName) &&
            strtoupper($record->getType()) === strtoupper($currentType)
        ) {
            if ($currentType === 'MX') {
                $mx = $record->getRdata();
                $existingNorm = normalizeMxRdata([
                    'preference' => $mx->getPreference(),
                    'exchange'   => $mx->getExchange(),
                ]);

                if (
                    $existingNorm['preference'] == $currentMxNorm['preference'] &&
                    $existingNorm['exchange'] === $currentMxNorm['exchange']
                ) {
                    $recordToUpdate = $record;
                    break;
                }
            } else {
                if (in_array($currentType, ['SPF', 'TXT'], true)) {
                    $existingNorm = normalizeSpfRdata($record->getRdata()->toText());
                    $currentNorm  = normalizeSpfRdata($currentRdata);

                    if ($existingNorm === $currentNorm) {
                        $recordToUpdate = $record;
                        break;
                    }
                } else {
                    if (strtolower($record->getRdata()->toText()) === strtolower(is_string($currentRdata) ? $currentRdata : '')) {
                        $recordToUpdate = $record;
                        break;
                    }
                }
            }
        }
    }

    if (!$recordToUpdate) {
        return [404, ['error' => 'Record not found']];
    }

    if ($newName) {
        $recordToUpdate->setName($newName);
    }
    if ($newTtl) {
        $recordToUpdate->setTtl($newTtl);
    }
    if ($newRdata) {
        try {
            $factoryMethods = [
                'A' => 'A',
                'AAAA' => 'AAAA',
                'CNAME' => 'CNAME',
                'MX' => 'MX',
                'NS' => 'NS',
                'PTR' => 'PTR',
                'SOA' => 'SOA',
                'TXT' => 'TXT',
                'SPF' => 'SPF',
                'DS' => 'DS',
            ];
            $normalizedType = strtoupper($currentType);
            if (!isset($factoryMethods[$normalizedType])) {
                return [400, ['error' => 'Unsupported record type']];
            }
            $methodName = $factoryMethods[$normalizedType];
            if ($currentType === 'MX') {
                $mx = normalizeMxRdata($newRdata);
                $rdataInstance = \Badcow\DNS\Rdata\Factory::MX($mx['preference'], $mx['exchange']);
            } else if ($currentType === 'DS') {
                $keytag = $newRdata['keytag'];
                $algorithm = $newRdata['algorithm'];
                $digestType = $newRdata['digestType'];
                $digest = $newRdata['digest'];
                $rdataInstance = \Badcow\DNS\Rdata\Factory::DS($keytag, $algorithm, hex2bin($digest), $digestType);
            } else {
                $rdataInstance = \Badcow\DNS\Rdata\Factory::$methodName($newRdata);
            }
            $recordToUpdate->setRdata($rdataInstance);
        } catch (Exception $e) {
            return [400, ['error' => 'Invalid RDATA: ' . $e->getMessage()]];
        }
    }
    if ($newComment) {
        $recordToUpdate->setComment($newComment);
    }

    // Update SOA serial for the zone update.
    updateZoneSoa($zone, $zoneName, $pdo);

    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [200, ['message' => 'Record updated successfully']];
}

/**
 * Handle deleting an existing DNS record.
 * Now receives $pdo to update the SOA record.
 */
function handleDeleteRecord($zoneName, $request, $pdo) {
    if (empty($zoneName) || !isValidDomainName($zoneName)) {
        return [400, ['error' => 'Invalid or empty zone name']];
    }

    try {
        $zone = loadZone($zoneName);
    } catch (Exception $e) {
        return [404, ['error' => $e->getMessage()]];
    }

    try {
        $body = json_decode($request->rawContent(), true, 512, JSON_THROW_ON_ERROR);

        if (empty($body) || !is_array($body)) {
            return [400, ['error' => 'Empty or invalid JSON payload']];
        }
    } catch (JsonException $e) {
        return [400, ['error' => 'Invalid JSON: ' . $e->getMessage()]];
    }

    $recordName = trim($body['name'] ?? '');
    $recordType = strtoupper(trim($body['type'] ?? ''));
    if ($recordType === 'MX' && rtrim($recordName, '.') === rtrim($zoneName, '.')) {
        $recordName = '@';
    }
    if ($recordType === 'DS' || $recordType === 'MX') {
        $recordRdata = $body['rdata'] ?? '';
    } else {
        $recordRdata = trim($body['rdata'] ?? '');
    }

    if (!$recordName || !$recordType || !$recordRdata) {
        return [400, ['error' => 'Record name, type, and rdata are required for identification']];
    }

    if ($recordType === 'MX') {
        $recordRdata = normalizeMxRdata($recordRdata);
    }

    $recordToDelete = null;
    foreach ($zone->getResourceRecords() as $record) {
        if (
            strtolower($record->getName()) === strtolower($recordName) &&
            strtoupper($record->getType()) === strtoupper($recordType)
        ) {
            if ($recordType === 'DS') {
                $dsRecord = $record->getRdata();

                $existingDigestHex = strtolower(bin2hex($dsRecord->getDigest()));
                $requestedDigestHex = strtolower($recordRdata['digest']);

                if (
                    $dsRecord->getKeyTag() == $recordRdata['keytag'] &&
                    $dsRecord->getAlgorithm() == $recordRdata['algorithm'] &&
                    $dsRecord->getDigestType() == $recordRdata['digestType'] &&
                    $existingDigestHex === $requestedDigestHex
                ) {
                    $recordToDelete = $record;
                    break;
                }
            } elseif ($recordType === 'MX') {
                $mxRecord = $record->getRdata();
                $existingNorm = normalizeMxRdata([
                    'preference' => $mxRecord->getPreference(),
                    'exchange'   => $mxRecord->getExchange(),
                ]);

                if (
                    $existingNorm['preference'] == $recordRdata['preference'] &&
                    $existingNorm['exchange'] === $recordRdata['exchange']
                ) {
                    $recordToDelete = $record;
                    break;
                }
            } else {
                if (in_array($recordType, ['SPF', 'TXT'], true)) {
                    $existingNorm  = normalizeSpfRdata($record->getRdata()->toText());
                    $requestedNorm = normalizeSpfRdata($recordRdata);

                    if ($existingNorm === $requestedNorm) {
                        $recordToDelete = $record;
                        break;
                    }
                } else {
                    if (strtolower($record->getRdata()->toText()) === strtolower($recordRdata)) {
                        $recordToDelete = $record;
                        break;
                    }
                }
            }
        }
    }

    if (!$recordToDelete) {
        return [404, ['error' => 'Record not found']];
    }

    $zone->remove($recordToDelete);

    // Update SOA serial for the zone update.
    updateZoneSoa($zone, $zoneName, $pdo);

    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [200, ['message' => 'Record deleted successfully']];
}

// Initialize Swoole HTTP Server
$server = new Server("0.0.0.0", 7650);
$server->set([
    'daemonize' => false,
    'log_file' => '/var/log/plexdns/bind9-api.log',
    'log_level' => SWOOLE_LOG_INFO,
    'worker_num' => swoole_cpu_num() * 2,
    'pid_file' => '/var/run/bind9-api.pid',
    'max_request' => 1000,
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
$log->info('BIND9 api server started at http://127.0.0.1:7650');

$server->on("request", function (Request $request, Response $response) use ($pool, $log, $rateLimiter) {
    $response->header("Content-Type", "application/json");

    $pdo = $pool->get();

    try {
        $remoteAddr = $request->server['remote_addr'] ?? '';
        if (!isIpWhitelisted($remoteAddr, $pdo)) {
            if (filter_var($_ENV['RATELY'] ?? false, FILTER_VALIDATE_BOOLEAN) && $rateLimiter->isRateLimited('bind9_api', $remoteAddr, $_ENV['RATE_LIMIT'], $_ENV['RATE_PERIOD'])) {
                $log->error('Rate limit exceeded for ' . $remoteAddr);
                $response->header('Content-Type', 'application/json');
                $response->status(429);
                $response->end(json_encode(['error' => 'Rate limit exceeded. Please try again later.']));
                return;
            }
        }

        $path = $request->server['request_uri'];
        $method = $request->server['request_method'];

        if ($path === '/login' && $method === 'POST') {
            list($status, $body) = handleLogin($request, $pdo);
            $response->status($status);
            $response->end(json_encode($body));
            return;
        }

        $user = authenticate($request, $pdo, $log);
        if (!$user) {
            $response->status(401);
            $response->end(json_encode(['error' => 'Unauthorized']));
            return;
        }

        // Zones Management
        if ($path === '/zones') {
            if ($method === 'GET') {
                list($status, $body) = handleGetZones();
                $response->status($status);
                $response->end(json_encode($body));
                return;
            } elseif ($method === 'POST') {
                list($status, $body) = handleAddZone($request, $pdo);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            }
        }

        // Slave Zone Management
        if ($path === '/slave-zones') {
            if ($method === 'GET') {
                list($status, $body) = handleGetSlaveZones();
                $response->status($status);
                $response->end(json_encode($body));
                return;
            } elseif ($method === 'POST') {
                list($status, $body) = handleAddSlaveZone($request);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            }
        }

        // Delete Zone: DELETE /zones/{zone}
        if (preg_match('#^/zones/([^/]+)$#', $path, $matches) && $method === 'DELETE') {
            $zoneName = $matches[1];
            list($status, $body) = handleDeleteZone($zoneName);
            $response->status($status);
            $response->end(json_encode($body));
            return;
        }

        // Delete Slave Zone: DELETE /slave-zones/{zone}
        if (preg_match('#^/slave-zones/([^/]+)$#', $path, $matches) && $method === 'DELETE') {
            $zoneName = $matches[1];
            list($status, $body) = handleDeleteSlaveZone($zoneName);
            $response->status($status);
            $response->end(json_encode($body));
            return;
        }

        // Records Management
        if (preg_match('#^/zones/([^/]+)/records$#', $path, $matches)) {
            $zoneName = $matches[1];
            if ($method === 'GET') {
                list($status, $body) = handleGetRecords($zoneName);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            } elseif ($method === 'POST') {
                list($status, $body) = handleAddRecord($zoneName, $request, $pdo);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            }
        }

        if (preg_match('#^/zones/([^/]+)/records/([^/]+)$#', $path, $matches)) {
            $zoneName = $matches[1];
            if ($method === 'PUT') {
                list($status, $body) = handleUpdateRecord($zoneName, $request, $pdo);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            } elseif ($method === 'DELETE') {
                list($status, $body) = handleDeleteRecord($zoneName, $request, $pdo);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            }
        }

        $log->info('Path Not Found');
        $response->status(404);
        $response->end(json_encode(['error' => 'Path Not Found']));
    } catch (PDOException $e) {
        $log->error('Database error: ' . $e->getMessage());
        $response->status(500);
        $response->header('Content-Type', 'application/json');
        $response->end(json_encode(['Database error:' => $e->getMessage()]));
    } catch (Throwable $e) {
        $log->error(sprintf(
            "Exception: %s in %s on line %d\nTrace:\n%s",
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
            $e->getTraceAsString()
        ));
        $response->status(500);
        $response->header('Content-Type', 'application/json');
        $response->end(json_encode(['Error:' => $e->getMessage()]));
    } finally {
        $pool->put($pdo);
    }
});

$server->start();

Swoole\Timer::tick(60000, function() use ($pool, $log) {
    $pdo = $pool->get();
    try {
        $stmt = $pdo->prepare("DELETE FROM sessions WHERE expires_at < NOW()");
        $stmt->execute();
        $removed = $stmt->rowCount();
        $log->info("Expired sessions cleanup executed, removed {$removed} sessions.");
    } catch (Exception $e) {
        $log->error("Failed to clean up expired sessions: " . $e->getMessage());
    } finally {
        $pool->put($pdo);
    }
});