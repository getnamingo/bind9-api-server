<?php
// server.php
require 'vendor/autoload.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Define users (In production, use a database)
$users = [
    'admin' => 'password123' // Use hashed passwords
];

// JWT Secret
$jwt_secret = $_ENV['JWT_SECRET'];

/**
 * Load and save zone files (unchanged from previous implementation).
 *
 * @param Badcow\DNS\Zone $zone
 * @throws Exception if unable to save the zone file
 */
function saveZone($zone) {
    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $zoneName = rtrim($zone->getName(), '.');
    $zoneFile = "$zoneDir/" . $zoneName . ".zone";
    $builder = new AlignedBuilder();
    if (file_put_contents($zoneFile, $builder->build($zone), LOCK_EX) === false) {
        throw new Exception("Failed to save zone file at $zoneFile");
    }
}

/**
 * Backup the configuration file before modifying.
 *
 * @param string $configFile
 * @throws Exception if unable to create a backup
 */
function backupConfigFile(string $configFile): void {
    $backupFile = $configFile . '.bak.' . date('YmdHis');

    if (!copy($configFile, $backupFile)) {
        throw new Exception("Failed to create backup of $configFile");
    }
}

/**
 * Remove a zone block from named.conf.local
 *
 * @param string $zoneName
 * @throws Exception if unable to modify the config file or zone block not found
 */
function removeZoneFromConfig(string $zoneName): void {
    $configFile = $_ENV['BIND9_CONF_FILE'];

    // Backup the config file before modifying
    backupConfigFile($configFile);

    // Read the current config file
    $configContent = file_get_contents($configFile);
    if ($configContent === false) {
        throw new Exception("Unable to read $configFile");
    }

    // Define a regex pattern to match the zone block
    $pattern = '/zone\s+"'.preg_quote($zoneName, '/').'"\s*\{[^}]*\};\n?/i';

    // Check if the zone block exists
    if (!preg_match($pattern, $configContent)) {
        throw new Exception("Zone block for '$zoneName' not found in $configFile");
    }

    // Remove the zone block
    $newConfigContent = preg_replace($pattern, '', $configContent, 1);

    if ($newConfigContent === null) {
        throw new Exception("Error occurred while removing the zone block");
    }

    // Write the updated config back to the file
    if (file_put_contents($configFile, $newConfigContent, LOCK_EX) === false) {
        throw new Exception("Unable to write to $configFile");
    }
}

/**
 * Append a new zone block to named.conf.local
 *
 * @param string $zoneName
 * @param string $zoneFilePath
 * @throws Exception if unable to write to the config file
 */
function addZoneToConfig(string $zoneName, string $zoneFilePath): void {
    $configFile = $_ENV['BIND9_CONF_FILE'];

    // Backup the config file before modifying
    backupConfigFile($configFile);

    // Define the zone block
    $zoneBlock = "\nzone \"$zoneName\" {\n    type master;\n    file \"$zoneFilePath\";\n};\n";

    // Append the zone block to the config file
    if (file_put_contents($configFile, $zoneBlock, FILE_APPEND | LOCK_EX) === false) {
        throw new Exception("Unable to write to $configFile");
    }
}

function loadZone($zoneName) {
    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $zoneFile = "$zoneDir/$zoneName.zone";
    if (!file_exists($zoneFile)) {
        throw new Exception("Zone file not found.");
    }
    $file = file_get_contents($zoneFile);
    $zone = Badcow\DNS\Parser\Parser::parse($zoneName.'.', $file);
    return $zone;
}

function reloadBIND9() {
    // Reload BIND9 configuration
    exec('sudo rndc reload', $output, $return_var);
    if ($return_var !== 0) {
        throw new Exception("Failed to reload BIND9: " . implode("\n", $output));
    }
}

// Authentication Middleware
function authenticate($request) {
    global $jwt_secret, $users;
    
    $debugMode = $_ENV['DEBUG_MODE'] === 'true';

    if ($debugMode) {
        // Attempt to authenticate using Basic Auth
        $authHeader = $request->header['authorization'] ?? '';
        if (preg_match('/Basic\s(\S+)/', $authHeader, $matches)) {
            $credentials = base64_decode($matches[1]);
            if ($credentials) {
                list($username, $password) = explode(':', $credentials, 2);
                if (isset($users[$username]) && $users[$username] === $password) {
                    // Authentication successful
                    return $username; // You can return user details if needed
                }
            }
        }

        // Alternatively, accept username and password via JSON body
        // Uncomment the following block if you prefer this method
        if (in_array($request->server['request_method'], ['POST', 'PUT'])) {
            $body = json_decode($request->rawContent(), true);
            $username = $body['username'] ?? '';
            $password = $body['password'] ?? '';
            if (isset($users[$username]) && $users[$username] === $password) {
                return $username;
            }
        }
    }

    // Proceed with JWT Authentication
    $authHeader = $request->header['authorization'] ?? '';
    if (!$authHeader) {
        return false;
    }
    
    // Support both Bearer tokens and Basic Auth if in debug mode
    $authParts = explode(' ', $authHeader, 2);
    if (count($authParts) !== 2) {
        return false;
    }

    list($type, $token) = $authParts;

    if (strcasecmp($type, 'Bearer') === 0) {
        if (!$token) {
            return false;
        }
        try {
            $decoded = JWT::decode($token, new Key($jwt_secret, 'HS256'));
            return $decoded;
        } catch (Exception $e) {
            return false;
        }
    }

    // If not Bearer, and not in debug mode, reject
    return false;
}

// Handler Functions
function handleLogin($request) {
    global $users, $jwt_secret;
    $body = json_decode($request->rawContent(), true);
    $username = $body['username'] ?? '';
    $password = $body['password'] ?? '';

    if (!isset($users[$username]) || $users[$username] !== $password) {
        return [401, ['error' => 'Invalid credentials']];
    }

    $payload = [
        'iss' => 'bind9-api',
        'iat' => time(),
        'exp' => time() + (60 * 60) // Token valid for 1 hour
    ];

    $jwt = JWT::encode($payload, $jwt_secret, 'HS256');
    return [200, ['token' => $jwt]];
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
function handleAddZone($request) {
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
        // Add default SOA and NS records
        $soa = new ResourceRecord;
        $soa->setName('@');
        $soa->setClass(Classes::INTERNET);
        $soa->setRdata(Factory::Soa(
            'ns1.example.com.',
            'hostmaster.example.com.',
            '2024041301',
            7200,
            3600,
            1209600,
            86400
        ));
        $zone->addResourceRecord($soa);

        $ns1 = new ResourceRecord;
        $ns1->setName('@');
        $ns1->setClass(Classes::INTERNET);
        $ns1->setRdata(Factory::Ns('ns1.example.com.'));
        $zone->addResourceRecord($ns1);

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
            'id' => spl_object_hash($record),
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
                case 'TXT':
                    if ($existingRecord->getRdata()->getText() === $rdata) {
                        return [400, ['error' => 'Record already exists']];
                    }
                    break;
                // Add additional cases for other record types as needed
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
        ];
        $normalizedType = strtoupper($type);
        if (!isset($factoryMethods[$normalizedType])) {
            return [400, ['error' => 'Unsupported record type']];
        }
        $methodName = $factoryMethods[$normalizedType];
        $rdataInstance = \Badcow\DNS\Rdata\Factory::$methodName($rdata);
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

function handleUpdateRecord($zoneName, $recordId, $request) {
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

    // Find the record by ID
    $found = false;
    foreach ($zone->getResourceRecords() as $record) {
        if (spl_object_hash($record) === $recordId) {
            if ($name) $record->setName($name);
            if ($type) $record->setType($type);
            if ($ttl) $record->setTtl($ttl);
            if ($rdata) {
                try {
                    $rdataClass = 'Badcow\DNS\Rdata\\' . ucfirst(strtolower($type));
                    if (!class_exists($rdataClass)) {
                        return [400, ['error' => 'Unsupported record type']];
                    }
                    $record->setRdata(new $rdataClass($rdata));
                } catch (Exception $e) {
                    return [400, ['error' => 'Invalid RDATA: ' . $e->getMessage()]];
                }
            }
            $found = true;
            break;
        }
    }

    if (!$found) {
        return [404, ['error' => 'Record not found']];
    }

    saveZone($zone);
    reloadBIND9();

    return [200, ['message' => 'Record updated successfully']];
}

function handleDeleteRecord($zoneName, $recordId) {
    try {
        $zone = loadZone($zoneName);
    } catch (Exception $e) {
        return [404, ['error' => $e->getMessage()]];
    }

    $found = false;
    foreach ($zone->getResourceRecords() as $key => $record) {
        if (spl_object_hash($record) === $recordId) {
            $zone->removeRecord($record);
            $found = true;
            break;
        }
    }

    if (!$found) {
        return [404, ['error' => 'Record not found']];
    }

    saveZone($zone);
    reloadBIND9();

    return [200, ['message' => 'Record deleted successfully']];
}

// Initialize Swoole HTTP Server
$server = new Server("0.0.0.0", 9501);

$server->on("start", function ($server) {
    echo "Swoole HTTP server started at http://127.0.0.1:9501\n";
});

$server->on("request", function (Request $request, Response $response) {
    // Set CORS headers if needed
    $response->header("Content-Type", "application/json");

    $path = $request->server['request_uri'];
    $method = $request->server['request_method'];

    // Routing
    // Authentication route does not require auth
    if ($path === '/login' && $method === 'POST') {
        list($status, $body) = handleLogin($request);
        $response->status($status);
        $response->end(json_encode($body));
        return;
    }

    // All other routes require authentication
    $user = authenticate($request);
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
            list($status, $body) = handleAddZone($request);
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
            list($status, $body) = handleUpdateRecord($zoneName, $recordId, $request);
            $response->status($status);
            $response->end(json_encode($body));
            return;
        } elseif ($method === 'DELETE') {
            list($status, $body) = handleDeleteRecord($zoneName, $recordId);
            $response->status($status);
            $response->end(json_encode($body));
            return;
        }
    }

    // If no route matched
    $response->status(404);
    $response->end(json_encode(['error' => 'Not Found']));
});

$server->start();
