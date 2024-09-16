<?php
require 'vendor/autoload.php';

use Dotenv\Dotenv;

// Load environment variables from .env file
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

try {
    // Database connection using PDO
    $dsn = "{$_ENV['DB_TYPE']}:host={$_ENV['DB_HOST']};port={$_ENV['DB_PORT']};dbname={$_ENV['DB_DATABASE']}";
    $pdo = new PDO($dsn, $_ENV['DB_USERNAME'], $_ENV['DB_PASSWORD'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // Input data (In a real application, get these values from a form or command line)
    $username = 'testuser';
    $password = 'securepassword';

    // Hash the password using Argon2id (most secure variant of Argon2)
    $hashedPassword = password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 1<<17,    // 128 MB
        'time_cost'   => 4,        // Number of iterations
        'threads'     => 2         // Parallelism (CPU cores)
    ]);

    // Prepare and execute the INSERT statement
    $stmt = $pdo->prepare('INSERT INTO users (username, password) VALUES (:username, :password)');
    $stmt->execute([
        ':username' => $username,
        ':password' => $hashedPassword,
    ]);

    echo "User '$username' created successfully.";

} catch (PDOException $e) {
    echo 'Database error: ' . $e->getMessage();
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}
