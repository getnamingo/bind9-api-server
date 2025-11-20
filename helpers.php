<?php

require __DIR__ . '/vendor/autoload.php';

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
 */
function setupLogger($logFilePath, $channelName = 'app') {
    $log = new Logger($channelName);
    $consoleHandler = new StreamHandler('php://stdout', Logger::DEBUG);
    $consoleFormatter = new LineFormatter(
        "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n",
        "Y-m-d H:i:s.u",
        true,
        true
    );
    $consoleHandler->setFormatter($consoleFormatter);
    $log->pushHandler($consoleHandler);

    $fileHandler = new RotatingFileHandler($logFilePath, 0, Logger::DEBUG);
    $fileFormatter = new LineFormatter(
        "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n",
        "Y-m-d H:i:s.u"
    );
    $fileHandler->setFormatter($fileFormatter);
    $log->pushHandler($fileHandler);

    return $log;
}

function isIpWhitelisted($ip, $pdo) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM whitelist WHERE ip_address = :ip");
    $stmt->execute(['ip' => $ip]);
    $count = $stmt->fetchColumn();
    return $count > 0;
}

/**
 * Save the zone file.
 */
function saveZone($zone) {
    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    $zoneName = rtrim($zone->getName(), '.');
    if (!isValidDomainName($zoneName)) {
        throw new Exception("Invalid zone name");
    }
    $zoneFile = "$zoneDir/" . $zoneName . ".zone";
    $builder = new AlignedBuilder();
    if (file_put_contents($zoneFile, $builder->build($zone), LOCK_EX) === false) {
        throw new Exception("Failed to save zone file at $zoneFile");
    }
}

/**
 * Backup the configuration file.
 */
function backupConfigFile(string $configFile): void {
    $backupFile = $configFile . '.bak.' . date('YmdHis');
    if (!file_exists($configFile) || !is_readable($configFile)) {
        throw new Exception("Invalid configuration file");
    }
    if (!copy($configFile, $backupFile)) {
        throw new Exception("Failed to create backup of $configFile");
    }
}

/**
 * Remove a zone block from named.conf.local.
 */
function removeZoneFromConfig(string $zoneName): void {
    $configFile = $_ENV['BIND9_CONF_FILE'];
    backupConfigFile($configFile);
    $configContent = file_get_contents($configFile);
    if ($configContent === false) {
        throw new Exception("Unable to read $configFile");
    }
    $pattern = '/zone\s+"'.preg_quote($zoneName, '/').'"\s*\{[^}]*\};\n?/i';
    if (!preg_match($pattern, $configContent)) {
        throw new Exception("Zone block for '$zoneName' not found in $configFile");
    }
    $newConfigContent = preg_replace($pattern, '', $configContent, 1);
    if ($newConfigContent === null) {
        throw new Exception("Error occurred while removing the zone block");
    }
    if (file_put_contents($configFile, $newConfigContent, LOCK_EX) === false) {
        throw new Exception("Unable to write to $configFile");
    }
}

/**
 * Remove a slave zone block from named.conf.local.
 */
function removeSlaveZoneFromConfig(string $zoneName): void {
    $configFile = $_ENV['BIND9_CONF_FILE'];
    backupConfigFile($configFile);
    $configContent = file_get_contents($configFile);
    if ($configContent === false) {
        throw new Exception("Unable to read $configFile");
    }
    $pattern = '/zone\s+"'.preg_quote($zoneName, '/').'"\s*\{[^}]*\};\n?/i';
    if (!preg_match($pattern, $configContent)) {
        throw new Exception("Slave zone block for '$zoneName' not found in $configFile");
    }
    $newConfigContent = preg_replace($pattern, '', $configContent, 1);
    if ($newConfigContent === null) {
        throw new Exception("Error occurred while removing the slave zone block");
    }
    if (file_put_contents($configFile, $newConfigContent, LOCK_EX) === false) {
        throw new Exception("Unable to write to $configFile");
    }
}

/**
 * Append a new zone block to named.conf.local.
 */
function addZoneToConfig(string $zoneName, string $zoneFilePath): void {
    $configFile = $_ENV['BIND9_CONF_FILE'];
    backupConfigFile($configFile);
    $zoneBlock = "\nzone \"$zoneName\" {\n    type master;\n    file \"$zoneFilePath\";\n};\n";
    if (file_put_contents($configFile, $zoneBlock, FILE_APPEND | LOCK_EX) === false) {
        throw new Exception("Unable to write to $configFile");
    }
}

/**
 * Append a new slave zone block to named.conf.local.
 */
function addSlaveZoneToConfig(string $zoneName, string $masterIp): void {
    $configFile = $_ENV['BIND9_CONF_FILE'];
    backupConfigFile($configFile);
    $zoneBlock = "\nzone \"$zoneName\" {\n    type slave;\n    masters { $masterIp; };\n    file \"/var/cache/bind/$zoneName.zone\";\n};\n";
    if (file_put_contents($configFile, $zoneBlock, FILE_APPEND | LOCK_EX) === false) {
        throw new Exception("Unable to write to $configFile");
    }
}

/**
 * Load a zone file.
 */
function loadZone($zoneName) {
    $zoneDir = $_ENV['BIND9_ZONE_DIR'];
    if (!isValidDomainName($zoneName)) {
        throw new Exception("Invalid zone name");
    }
    $zoneFile = "$zoneDir/$zoneName.zone";
    if (!file_exists($zoneFile)) {
        throw new Exception("Zone file not found.");
    }
    $file = file_get_contents($zoneFile);
    $zone = Badcow\DNS\Parser\Parser::parse($zoneName.'.', $file);
    return $zone;
}

/**
 * Reload BIND9 configuration and notify slaves.
 */
function reloadBIND9() {
    exec('sudo rndc reload', $output, $return_var);
    if ($return_var !== 0) {
        throw new Exception(implode("\n", $output));
    }
    exec('sudo rndc notify 2>&1', $notify_output, $notify_return_var);
    if ($notify_return_var !== 0) {
        error_log("Failed to notify slave servers: " . implode("\n", $notify_output));
    }
}

/**
 * Authentication middleware.
 */
function authenticate($request, $pdo, $log) {
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
            return false;
        }
        if (strtotime($session['expires_at']) < time()) {
            return false;
        }
        return [
            'user_id' => $session['user_id'],
            'username' => $session['username']
        ];
    } catch (Exception $e) {
        $log->error('Authentication error: ' . $e->getMessage());
        return false;
    }
}

function generateInitialSerialNumber() {
    $currentDate = date('Ymd');
    return $currentDate . '01';
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
    $currentDate = date('Ymd');
    $serialDate = substr($currentSerial, 0, 8);
    $changeNumber = (int)substr($currentSerial, 8, 2);

    if ($serialDate === $currentDate) {
        $changeNumber++;
        $changeNumber = str_pad($changeNumber, 2, '0', STR_PAD_LEFT);
    } else {
        $changeNumber = '01';
    }

    $newSerial = $currentDate . $changeNumber;
    $stmt = $pdo->prepare('UPDATE zones SET current_soa = :serial_number WHERE domain_name = :domain_name');
    $stmt->execute([':serial_number' => $newSerial, ':domain_name' => $domainName]);
    return $newSerial;
}

/**
 * Update the SOA record in the zone by updating its serial number.
 */
function updateZoneSoa($zone, $zoneName, $pdo) {
    $newSerial = updateSerialNumberFromZone($zone);
    foreach ($zone->getResourceRecords() as $record) {
        if (strtoupper($record->getType()) === 'SOA') {
            $soaRdata = $record->getRdata();
            $soaRdata->setSerial($newSerial);
            $record->setRdata($soaRdata);
            break;
        }
    }
    saveZone($zone);
}

function isValidDomainName($domain) {
    return preg_match('/^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/', $domain) || // Regular domain
           preg_match('/^xn--[a-zA-Z0-9-]+$/', $domain); // IDN (Punycode)
}

function updateSerialNumberFromZone($zone) {
    $currentDate = date('Ymd');
    $newSerial = null;

    foreach ($zone->getResourceRecords() as $record) {
        if (strtoupper($record->getType()) === 'SOA') {
            $currentSerial = $record->getRdata()->getSerial();
            $serialDate = substr($currentSerial, 0, 8);
            $changeNumber = (int)substr($currentSerial, 8, 2);

            if ($serialDate === $currentDate) {
                $changeNumber++;
                $changeNumber = str_pad($changeNumber, 2, '0', STR_PAD_LEFT);
            } else {
                $changeNumber = '01';
            }

            $newSerial = $currentDate . $changeNumber;
            break;
        }
    }

    return $newSerial;
}

function normalizeMxRdata($rdata): array {
    if (is_string($rdata)) {
        $parts = preg_split('/\s+/', trim($rdata), 2);
        if (count($parts) === 2 && is_numeric($parts[0])) {
            return [
                'preference' => (int) $parts[0],
                'exchange'   => rtrim($parts[1], '.') . '.',
            ];
        }
        // fallback
        return [
            'preference' => 10,
            'exchange'   => rtrim($rdata, '.') . '.',
        ];
    }

    return [
        'preference' => (int)($rdata['preference'] ?? 10),
        'exchange'   => rtrim($rdata['exchange'] ?? '', '.') . '.',
    ];
}

function normalizeSpfRdata($rdata): string
{
    // Allow array or string input
    if (is_array($rdata)) {
        $rdata = implode(' ', $rdata);
    }

    $rdata = trim((string)$rdata);

    if ($rdata === '') {
        return '';
    }

    // Strip surrounding quotes if present
    $first = $rdata[0];
    $last  = $rdata[strlen($rdata) - 1];
    if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) {
        $rdata = substr($rdata, 1, -1);
    }

    // Collapse internal whitespace
    $rdata = preg_replace('/\s+/', ' ', $rdata);

    // SPF is case-insensitive; normalize to lowercase for comparison
    return strtolower($rdata);
}