<?php
// Connects as a non-root, least-privilege DB user (F10, CWE-250).
// Credentials come from the environment; nothing hardcoded.
$server   = getenv('DB_SERVER');
$username = getenv('DB_USER');
$password = getenv('DB_PASSWORD');
$database = getenv('DB_NAME');

try {
    $conn = new PDO(
        "mysql:host=$server;dbname=$database;charset=utf8mb4",
        $username,
        $password,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES   => false,   // real server-side prepares
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );
} catch (PDOException $e) {
    // Log the detail, never leak it to the client (F22, CWE-209/200).
    error_log('DB connection failed: ' . $e->getMessage());
    http_response_code(500);
    exit(json_encode(['status' => '500', 'statusDescription' => 'Internal error']));
}
