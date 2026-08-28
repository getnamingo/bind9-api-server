<?php

declare(strict_types=1);

use Dotenv\Dotenv;
use Namingo\Bind9Api\Database;

require __DIR__ . '/vendor/autoload.php';

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$username = trim((string) ($argv[1] ?? ''));
if (!preg_match('/^[A-Za-z0-9_.@-]{3,50}$/', $username)) {
    fwrite(STDERR, "Usage: printf '%s' 'a-long-password' | php create_user.php USERNAME\n");
    fwrite(STDERR, "USERNAME must be 3-50 characters: letters, digits, _, ., @ or -.\n");
    exit(2);
}

$password = rtrim((string) stream_get_contents(STDIN), "\r\n");
if (strlen($password) < 12 || strlen($password) > 1024) {
    fwrite(STDERR, "Read a password of 12-1024 bytes from standard input.\n");
    exit(2);
}

try {
    Dotenv::createImmutable(__DIR__)->load();
    $pdo = (new Database($_ENV))->connect();
    $algorithm = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    $hash = password_hash($password, $algorithm);
    if ($hash === false) {
        throw new RuntimeException('Unable to hash the password.');
    }

    $statement = $pdo->prepare('INSERT INTO users (username, password) VALUES (:username, :password)');
    $statement->execute(['username' => $username, 'password' => $hash]);

    fwrite(STDOUT, "User '{$username}' created successfully.\n");
} catch (Throwable $exception) {
    fwrite(STDERR, 'Unable to create user: ' . $exception->getMessage() . PHP_EOL);
    exit(1);
}
