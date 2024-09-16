<?php

require_once 'vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Formatter\LineFormatter;
use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
use Namingo\Rately\Rately;

/**
 * Sets up and returns a Logger instance.
 * 
 * @param string $logFilePath Full path to the log file.
 * @param string $channelName Name of the log channel (optional).
 * @return Logger
 */
function setupLogger($logFilePath, $channelName = 'app') {
    // Create a log channel
    $log = new Logger($channelName);

    // Set up the console handler
    $consoleHandler = new StreamHandler('php://stdout', Logger::DEBUG);
    $consoleFormatter = new LineFormatter(
        "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n",
        "Y-m-d H:i:s.u", // Date format
        true, // Allow inline line breaks
        true  // Ignore empty context and extra
    );
    $consoleHandler->setFormatter($consoleFormatter);
    $log->pushHandler($consoleHandler);

    // Set up the file handler
    $fileHandler = new RotatingFileHandler($logFilePath, 0, Logger::DEBUG);
    $fileFormatter = new LineFormatter(
        "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n",
        "Y-m-d H:i:s.u" // Date format
    );
    $fileHandler->setFormatter($fileFormatter);
    $log->pushHandler($fileHandler);

    return $log;
}

function isIpWhitelisted($ip, $pdo) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM whitelist WHERE ip_address = ?");
    $stmt->execute([$ip]);
    $count = $stmt->fetchColumn();
    return $count > 0;
}

// Function to update the permitted IPs from the database
function updatePermittedIPs($pool, $permittedIPsTable) {
    $pdo = $pool->get();
    $query = "SELECT ip_address FROM whitelist";
    $stmt = $pdo->query($query);
    $permittedIPs = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    $pool->put($pdo);

    // Manually clear the table by removing each entry
    foreach ($permittedIPsTable as $key => $value) {
        $permittedIPsTable->del($key);
    }

    // Insert new values
    foreach ($permittedIPs as $ip) {
        $permittedIPsTable->set($ip, ['ip_address' => $ip]);
    }
}

/**
 * Load and save zone files.
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

    // Notify slave servers
    exec('sudo rndc notify', $notify_output, $notify_return_var);
    if ($notify_return_var !== 0) {
        throw new Exception("Failed to notify slave servers: " . implode("\n", $notify_output));
    }
}

// Authentication Middleware
function authenticate($request, $pdo, $log) {
    // Get the token from the Authorization header
    $authHeader = $request->header['authorization'] ?? '';
    if (!$authHeader) {
        return false;
    }

    $authParts = explode(' ', $authHeader, 2);
    if (count($authParts) !== 2 || strcasecmp($authParts[0], 'Bearer') !== 0) {
        return false;
    }

    $token = $authParts[1];

    if (!$token) {
        return false;
    }

    try {
        // Prepare statement to fetch session securely
        $stmt = $pdo->prepare('
            SELECT s.user_id, u.username, s.expires_at, s.ip_address, s.user_agent
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = :token
            LIMIT 1
        ');
        $stmt->execute(['token' => $token]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$session) {
            // Invalid token
            return false;
        }

        // Check if the session has expired
        if (strtotime($session['expires_at']) < time()) {
            // Session has expired
            return false;
        }

        // Authentication successful
        // Return user information (e.g., user ID and username)
        return [
            'user_id' => $session['user_id'],
            'username' => $session['username']
        ];
    } catch (Exception $e) {
        // Log the exception internally without exposing details to the client
        $log->error('Authentication error: ' . $e->getMessage());
        return false;
    }
}

function generateInitialSerialNumber() {
    $currentDate = date('Ymd'); // YYYYMMDD
    return $currentDate . '01';  // Initial serial number
}

function getCurrentSerialNumber($pdo, $domainName) {
    $stmt = $pdo->prepare('SELECT current_soa FROM zones WHERE domain_name = :domain_name');
    $stmt->execute([':domain_name' => $domainName]);
    return $stmt->fetchColumn();
}

function insertInitialSerialNumber($pdo, $domainName) {
    $serialNumber = generateInitialSerialNumber();
    $stmt = $pdo->prepare('INSERT INTO zones (domain_name, current_soa, created_at, updated_at) VALUES (:domain_name, :serial_number, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)');
    $stmt->execute([':domain_name' => $domainName, ':serial_number' => $serialNumber]);
    return $serialNumber;
}

function updateSerialNumber($pdo, $domainName) {
    $currentSerial = getCurrentSerialNumber($pdo, $domainName);
    $currentDate = date('Ymd'); // YYYYMMDD

    // Extract date and change number (NN) from current serial number
    $serialDate = substr($currentSerial, 0, 8);
    $changeNumber = (int)substr($currentSerial, 8, 2);

    if ($serialDate === $currentDate) {
        // Increment the change number
        $changeNumber++;
        if ($changeNumber < 10) {
            $changeNumber = '0' . $changeNumber; // Ensure it is two digits
        }
    } else {
        // New date, reset change number to '01'
        $changeNumber = '01';
    }

    // Construct new serial number
    $newSerial = $currentDate . $changeNumber;

    // Update serial number in the database
    $stmt = $pdo->prepare('UPDATE zones SET current_soa = :serial_number WHERE domain_name = :domain_name');
    $stmt->execute([':serial_number' => $newSerial, ':domain_name' => $domainName]);

    return $newSerial;
}