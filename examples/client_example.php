<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use Namingo\Bind9Api\ApiClient;

$url = getenv('BIND9_API_URL') ?: 'https://api.example.com';
$username = getenv('BIND9_API_USERNAME') ?: '';
$password = getenv('BIND9_API_PASSWORD') ?: '';

if ($username === '' || $password === '') {
    fwrite(STDERR, "Set BIND9_API_USERNAME and BIND9_API_PASSWORD first.\n");
    exit(1);
}

try {
    $api = new ApiClient($url);
    $api->login($username, $password);

    print_r($api->getZones());

    // More examples:
    // $api->addZone('example.com');
    // $api->addRecord('example.com', [
    //     'name' => 'www',
    //     'type' => 'A',
    //     'ttl' => 3600,
    //     'rdata' => '192.0.2.10',
    // ]);
    // $api->updateRecord(
    //     'example.com',
    //     ['name' => 'www', 'type' => 'A', 'rdata' => '192.0.2.10'],
    //     ['rdata' => '192.0.2.11']
    // );
    // $api->deleteRecord('example.com', [
    //     'name' => 'www', 'type' => 'A', 'rdata' => '192.0.2.11',
    // ]);
} catch (Throwable $exception) {
    fwrite(STDERR, 'Error: ' . $exception->getMessage() . PHP_EOL);
    exit(1);
}
