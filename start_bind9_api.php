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
use Badcow\DNS\AlignedBuilder;
use Namingo\Rately\Rately;

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$logFilePath = '/var/log/namingo/bind9_api.log';
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
    $body = json_decode($request->rawContent(), true);
    $username = trim($body['username'] ?? '');
    $password = $body['password'] ?? '';

    if (empty($username) || empty($password)) {
        return [400, ['error' => 'Username and password are required']];
    }

    try {
        // Prepare statement to fetch user securely
        $stmt = $pdo->prepare('SELECT id, password FROM users WHERE username = :username LIMIT 1');
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Check if user exists and verify password
        if (!$user || !password_verify($password, $user['password'])) {
            // Authentication failed
            return [401, ['error' => 'Invalid credentials']];
        }

        // Generate secure session token
        $token = bin2hex(random_bytes(32)); // Generates a 64-character token

        // Store session token in the database
        $stmt = $pdo->prepare('
            INSERT INTO sessions (user_id, token, ip_address, user_agent, created_at, expires_at)
            VALUES (:user_id, :token, :ip_address, :user_agent, NOW(), DATE_ADD(NOW(), INTERVAL 1 HOUR))
        ');

        $ipAddress = inet_pton($request->server['remote_addr'] ?? ''); // Store IP address in binary format
        $userAgent = substr($request->header['user-agent'] ?? '', 0, 255); // Limit user agent length to 255 characters

        $stmt->execute([
            'user_id' => $user['id'],
            'token' => $token,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent
        ]);

        // Return session token to the client
        return [200, ['token' => $token]];
    } catch (Exception $e) {
        // Log the exception internally without exposing details to the client
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

/**
 * Handle adding a new zone.
 *
 * @param Swoole\Http\Request $request
 * @return array [status_code, response_body]
 */
function handleAddZone($request, $pdo) {
    $body = json_decode($request->rawContent(), true);
    $zoneName = trim($body['zone'] ?? '');

    if (!$zoneName) {
        return [400, ['error' => 'Zone name is required']];
    }
    
    // Validate zone name (basic validation)
    if (!preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $zoneName)) {
        return [400, ['error' => 'Invalid zone name format']];
    }

    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $zoneFile = "$zoneDir/$zoneName.zone";

    if (file_exists($zoneFile)) {
        return [409, ['error' => 'Zone already exists']];
    }

    // Create the zone using Badcow\DNS
    try {
        $zone = new Zone($zoneName.'.');
        
        $serialNumber = getCurrentSerialNumber($pdo, $zoneName);

        if (!$serialNumber) {
            // No serial number found, insert the initial one
            $serialNumber = insertInitialSerialNumber($pdo, $zoneName);
        } else {
            // Update the serial number
            $serialNumber = updateSerialNumber($pdo, $zoneName);
        }
        
        // Add default SOA and NS records
        $soa = new ResourceRecord;
        $soa->setName('@');
        $soa->setClass(Classes::INTERNET);
        $soa->setRdata(Factory::Soa(
            $_ENV['NS1'],
            $_ENV['SOA_EMAIL'],
            $serialNumber,
            $_ENV['REFRESH'],
            $_ENV['RETRY'],
            $_ENV['EXPIRE'],
            $_ENV['MIN_TTL']
        ));
        $zone->addResourceRecord($soa);

        // Add NS records (NS1 to NS13)
        for ($i = 1; $i <= 13; $i++) {
            $nsKey = 'NS' . $i;
            if (isset($_ENV[$nsKey])) {
                $nsRecord = new ResourceRecord;
                $nsRecord->setName('@');
                $nsRecord->setClass(Classes::INTERNET);
                $nsRecord->setRdata(Factory::Ns($_ENV[$nsKey]));
                $zone->addResourceRecord($nsRecord);
            }
        }

        saveZone($zone);
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to create zone file: ' . $e->getMessage()]];
    }

    // Update named.conf.local
    try {
        addZoneToConfig($zoneName, $zoneFile);
    } catch (Exception $e) {
        // Clean up by removing the created zone file
        unlink($zoneFile);
        return [500, ['error' => 'Failed to update named.conf.local: ' . $e->getMessage()]];
    }

    // Reload BIND9 to apply changes
    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [201, ['message' => 'Zone created successfully']];
}

/**
 * Handle deleting an existing zone.
 *
 * @param string $zoneName
 * @return array [status_code, response_body]
 */
function handleDeleteZone($zoneName) {
    $zoneName = trim($zoneName);

    if (!$zoneName) {
        return [400, ['error' => 'Zone name is required']];
    }

    // Validate zone name (basic validation)
    if (!preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $zoneName)) {
        return [400, ['error' => 'Invalid zone name format']];
    }

    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $zoneFile = "$zoneDir/$zoneName.zone";

    if (!file_exists($zoneFile)) {
        return [404, ['error' => 'Zone file does not exist']];
    }

    // Remove zone block from named.conf.local
    try {
        removeZoneFromConfig($zoneName);
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to update named.conf.local: ' . $e->getMessage()]];
    }

    // Delete the zone file
    if (!unlink($zoneFile)) {
        return [500, ['error' => 'Failed to delete zone file']];
    }

    // Reload BIND9 to apply changes
    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [200, ['message' => 'Zone deleted successfully']];
}

function handleGetRecords($zoneName) {
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

function handleAddRecord($zoneName, $request) {
    try {
        $zone = loadZone($zoneName);
    } catch (Exception $e) {
        return [404, ['error' => $e->getMessage()]];
    }

    $body = json_decode($request->rawContent(), true);
    $name = $body['name'] ?? '';
    $type = strtoupper($body['type'] ?? '');
    $ttl = $body['ttl'] ?? 3600;
    $rdata = $body['rdata'] ?? '';

    if (!$name || !$type || !$rdata) {
        return [400, ['error' => 'Missing required fields']];
    }

    // Check if the record already exists in the zone
    foreach ($zone->getResourceRecords() as $existingRecord) {
        if ($existingRecord->getName() === $name && $existingRecord->getRdata()->getType() === $type) {
            // Compare the Rdata based on type
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
                    if ($existingRecord->getRdata()->getExchange() === $rdata['exchange'] &&
                        $existingRecord->getRdata()->getPreference() == $rdata['preference']) {
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
                    if ($existingRecord->getRdata()->getText() === $rdata) {
                        return [400, ['error' => 'Record already exists']];
                    }
                    break;
                default:
                    return [400, ['error' => 'Unsupported record type']];
            }
        }
    }

    // Create a new DNS resource record
    $record = new ResourceRecord;
    $record->setName($name);
    if (is_numeric($ttl)) {
        $record->setTtl($ttl);
    }
    $record->setClass(Classes::INTERNET);

    // Dynamically create Rdata based on type
    try {
        // Mapping record types to Factory methods
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
            $preference = $rdata['preference'];
            $exchange = $rdata['exchange'];
            $rdataInstance = \Badcow\DNS\Rdata\Factory::MX($preference, $exchange);
        } else {
            $rdataInstance = \Badcow\DNS\Rdata\Factory::$methodName($rdata);
        }
        $record->setRdata($rdataInstance);
    } catch (Exception $e) {
        return [400, ['error' => 'Invalid RDATA: ' . $e->getMessage()]];
    }

    // Add the record to the zone and save
    $zone->addResourceRecord($record);
    saveZone($zone);
    reloadBIND9();

    return [201, ['message' => 'Record added successfully']];
}

/**
 * Handle updating an existing DNS record.
 *
 * @param string $zoneName The name of the DNS zone.
 * @param Swoole\Http\Request $request The HTTP request containing update details.
 * @return array [status_code, response_body]
 */
function handleUpdateRecord($zoneName, $request) {
    try {
        $zone = loadZone($zoneName);
    } catch (Exception $e) {
        return [404, ['error' => $e->getMessage()]];
    }

    $body = json_decode($request->rawContent(), true);

    // Extract identifying information for the record to be updated
    $currentName = trim($body['current_name'] ?? '');
    $currentType = strtoupper(trim($body['current_type'] ?? ''));
    $currentRdata = trim($body['current_rdata'] ?? '');

    // Extract new data for the record
    $newName = trim($body['new_name'] ?? $currentName);
    $newTtl = isset($body['new_ttl']) ? intval($body['new_ttl']) : 3600;
    $newRdata = trim($body['new_rdata'] ?? $currentRdata);
    $newComment = trim($body['new_comment'] ?? '');

    if (!$currentName || !$currentType || !$currentRdata) {
        return [400, ['error' => 'Current record name, type, and rdata are required for identification']];
    }

    // Find the record by current_name, current_type, and current_rdata
    $recordToUpdate = null;
    foreach ($zone->getResourceRecords() as $record) {
        if (
            strtolower($record->getName()) === strtolower($currentName) &&
            strtoupper($record->getType()) === strtoupper($currentType) &&
            strtolower($record->getRdata()->toText()) === strtolower($currentRdata)
        ) {
            $recordToUpdate = $record;
            break;
        }
    }

    if (!$recordToUpdate) {
        return [404, ['error' => 'Record not found']];
    }

    // Update the record with new values
    if ($newName) {
        $recordToUpdate->setName($newName);
    }
    if ($newTtl) {
        $recordToUpdate->setTtl($newTtl);
    }
    if ($newRdata) {
        // Dynamically create Rdata based on type
        try {
            // Mapping record types to Factory methods
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
            if ($type === 'MX') {
                $preference = $newRdata['preference'];
                $exchange = $newRdata['exchange'];
                $rdataInstance = \Badcow\DNS\Rdata\Factory::MX($preference, $exchange);
            } else {
                $rdataInstance = \Badcow\DNS\Rdata\Factory::$methodName($newRdata);
            }
            $record->setRdata($rdataInstance);
        } catch (Exception $e) {
            return [400, ['error' => 'Invalid RDATA: ' . $e->getMessage()]];
        }
    }
    if ($newComment) {
        $recordToUpdate->setComment($newComment);
    }

    // Save the updated zone
    try {
        saveZone($zone);
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to save updated zone: ' . $e->getMessage()]];
    }

    // Reload BIND9 to apply changes
    try {
        reloadBIND9();
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to reload BIND9: ' . $e->getMessage()]];
    }

    return [200, ['message' => 'Record updated successfully']];
}

/**
 * Handle deleting an existing DNS record.
 *
 * @param string $zoneName The name of the DNS zone.
 * @param Swoole\Http\Request $request The HTTP request containing deletion details.
 * @return array [status_code, response_body]
 */
function handleDeleteRecord($zoneName, $request) {
    try {
        $zone = loadZone($zoneName);
    } catch (Exception $e) {
        return [404, ['error' => $e->getMessage()]];
    }

    $body = json_decode($request->rawContent(), true);

    // Extract identifying information for the record to be deleted
    $recordName = trim($body['name'] ?? '');
    $recordType = strtoupper(trim($body['type'] ?? ''));
    $recordRdata = trim($body['rdata'] ?? '');

    if (!$recordName || !$recordType || !$recordRdata) {
        return [400, ['error' => 'Record name, type, and rdata are required for identification']];
    }

    // Find the record by name, type, and rdata
    $recordToDelete = null;
    foreach ($zone->getResourceRecords() as $record) {
        if (
            strtolower($record->getName()) === strtolower($recordName) &&
            strtoupper($record->getType()) === strtoupper($recordType) &&
            strtolower($record->getRdata()->toText()) === strtolower($recordRdata)
        ) {
            $recordToDelete = $record;
            break;
        }
    }

    if (!$recordToDelete) {
        return [404, ['error' => 'Record not found']];
    }

    // Remove the record from the zone
    $zone->remove($recordToDelete);

    // Save the updated zone
    try {
        saveZone($zone);
    } catch (Exception $e) {
        return [500, ['error' => 'Failed to save updated zone: ' . $e->getMessage()]];
    }

    // Reload BIND9 to apply changes
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
    'log_file' => '/var/log/namingo/bind9-api.log',
    'log_level' => SWOOLE_LOG_INFO,
    'worker_num' => swoole_cpu_num() * 2,
    'pid_file' => '/var/run/bind9-api.pid',
    'max_request' => 1000,
    'dispatch_mode' => 1,
    'open_tcp_nodelay' => true,
    'max_conn' => 1024,
    'buffer_output_size' => 2 * 1024 * 1024,  // 2MB
    'heartbeat_check_interval' => 60,
    'heartbeat_idle_time' => 600,  // 10 minutes
    'package_max_length' => 2 * 1024 * 1024,  // 2MB
    'reload_async' => true,
    'http_compression' => true
]);

$rateLimiter = new Rately();
$log->info('BIND9 api server started at http://127.0.0.1:7650');

$server->on("request", function (Request $request, Response $response) use ($pool, $log, $rateLimiter) {
    // Set CORS headers if needed
    $response->header("Content-Type", "application/json");
    
    // Get a PDO connection from the pool
    $pdo = $pool->get();

    $remoteAddr = $request->server['remote_addr'];
    if (!isIpWhitelisted($remoteAddr, $pdo)) {
        if (($_ENV['RATELY'] == true) && ($rateLimiter->isRateLimited('bind9_api', $remoteAddr, $_ENV['RATE_LIMIT'], $_ENV['RATE_PERIOD']))) {
            $log->error('rate limit exceeded for ' . $remoteAddr);
            $response->header('Content-Type', 'application/json');
            $response->status(429);
            $response->end(json_encode(['error' => 'Rate limit exceeded. Please try again later.']));
        }
    }

    try {
        $path = $request->server['request_uri'];
        $method = $request->server['request_method'];

        // Routing
        // Authentication route does not require auth
        if ($path === '/login' && $method === 'POST') {
            list($status, $body) = handleLogin($request, $pdo);
            $response->status($status);
            $response->end(json_encode($body));
            return;
        }

        // All other routes require authentication
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

        // Delete Zone: DELETE /zones/{zone}
        if (preg_match('#^/zones/([^/]+)$#', $path, $matches) && $method === 'DELETE') {
            $zoneName = $matches[1];
            list($status, $body) = handleDeleteZone($zoneName);
            $response->status($status);
            $response->end(json_encode($body));
            return;
        }

        // Records Management
        // GET /zones/{zone}/records
        if (preg_match('#^/zones/([^/]+)/records$#', $path, $matches)) {
            $zoneName = $matches[1];
            if ($method === 'GET') {
                list($status, $body) = handleGetRecords($zoneName);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            } elseif ($method === 'POST') {
                list($status, $body) = handleAddRecord($zoneName, $request);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            }
        }

        // Update/Delete Record: PUT or DELETE /zones/{zone}/records/{record_id}
        if (preg_match('#^/zones/([^/]+)/records/([^/]+)$#', $path, $matches)) {
            $zoneName = $matches[1];
            $recordId = $matches[2];
            if ($method === 'PUT') {
                list($status, $body) = handleUpdateRecord($zoneName, $request);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            } elseif ($method === 'DELETE') {
                list($status, $body) = handleDeleteRecord($zoneName, $request);
                $response->status($status);
                $response->end(json_encode($body));
                return;
            }
        }

        // If no route matched
        $log->info('Path Not Found');
        $response->status(404);
        $response->end(json_encode(['error' => 'Path Not Found']));
    } catch (PDOException $e) {
        // Handle database exceptions
        $log->error('Database error: ' . $e->getMessage());
        $response->status(500);
        $response->header('Content-Type', 'application/json');
        $response->end(json_encode(['Database error:' => $e->getMessage()]));
    } catch (Throwable $e) {
        // Catch any other exceptions or errors
        $log->error('Error: ' . $e->getMessage());
        $response->status(500);
        $response->header('Content-Type', 'application/json');
        $response->end(json_encode(['Error:' => $e->getMessage()]));
    } finally {
        // Return the connection to the pool
        $pool->put($pdo);
    }
});

$server->start();
