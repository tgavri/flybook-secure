<?php
require 'database.php';

// --- Defence in depth: security headers (F18/F19/F21, CWE-79/693) ---
header('Content-Type: application/json');
header("Content-Security-Policy: default-src 'self'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

// --- API key compared in constant time, read from env not hardcoded (F06, CWE-798) ---
$API_KEY = getenv('API_KEY') ?: '';
if (!hash_equals($API_KEY, $_GET['API_KEY'] ?? '')) {
    http_response_code(401);
    echo json_encode(['status' => '401', 'statusDescription' => 'Unauthorized']);
    exit;
}

switch ($_GET['action'] ?? '') {
    case 'get':   Get();   break;   // read-only, stays GET
    case 'login': Login(); break;   // POST only
    case 'book':  Book();  break;   // POST only
    default:
        http_response_code(400);
        echo json_encode(['status' => '400', 'statusDescription' => 'Bad request']);
}

// Read-only search. Prepared statements with bound parameters (F03, CWE-89).
function Get() {
    global $conn;
    switch ($_GET['items'] ?? '') {
        case 'airport':
            $stmt = $conn->prepare(
                'SELECT airport, code FROM airports WHERE airport LIKE :q OR code LIKE :q'
            );
            $stmt->bindValue(':q', '%' . ($_GET['search'] ?? '') . '%', PDO::PARAM_STR);
            $stmt->execute();
            respond($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;

        case 'flights':
            $stmt = $conn->prepare(
                'SELECT * FROM flights
                  WHERE (SUBSTRING(date_time_depart,1,10) = :d
                         OR SUBSTRING(date_time_arriv,1,10) = :d)
                    AND airport_from = :from
                    AND airport_to   = :to'
            );
            $stmt->bindValue(':d',    $_GET['date'] ?? '', PDO::PARAM_STR);
            $stmt->bindValue(':from', $_GET['from'] ?? '', PDO::PARAM_INT);
            $stmt->bindValue(':to',   $_GET['to']   ?? '', PDO::PARAM_INT);
            $stmt->execute();
            respond($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;

        default:
            http_response_code(400);
            echo json_encode(['status' => '400', 'statusDescription' => 'Bad request']);
    }
}

// Credentials via POST body, not the URL (F07, CWE-598).
function Login() {
    global $conn;
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { methodNotAllowed(); return; }

    $email = $_POST['email'] ?? '';
    $pass  = $_POST['pass']  ?? '';

    $stmt = $conn->prepare('SELECT * FROM passengers WHERE email = :email');
    $stmt->bindValue(':email', $email, PDO::PARAM_STR);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // bcrypt/Argon2 verify instead of unsalted MD5 (F05, CWE-916).
    // Requires passwords stored with password_hash(); see SECURITY-FIXES.md for migration.
    if ($user && password_verify($pass, $user['password'])) {
        // Cryptographically secure token, not md5(rand()) (F23, CWE-330/338).
        $token = bin2hex(random_bytes(32));
        $upd = $conn->prepare('UPDATE passengers SET token = :t WHERE id = :id');
        $upd->bindValue(':t',  $token,       PDO::PARAM_STR);
        $upd->bindValue(':id', $user['id'],  PDO::PARAM_INT);
        $upd->execute();

        unset($user['password']);           // never return the hash
        $user['token'] = $token;
        echo json_encode(['status' => '200', 'statusDescription' => 'Ok', 'user' => $user]);
    } else {
        http_response_code(401);
        echo json_encode(['status' => '450', 'statusDescription' => 'Invalid credentials']);
    }
}

// State change via POST; user is derived from the token, never trusted from the request (F08/F09, CWE-639/352).
function Book() {
    global $conn;
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { methodNotAllowed(); return; }

    $token  = $_POST['token']  ?? '';
    $flight = $_POST['flight'] ?? '';

    $stmt = $conn->prepare('SELECT id FROM passengers WHERE token = :token');
    $stmt->bindValue(':token', $token, PDO::PARAM_STR);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        http_response_code(401);
        echo json_encode(['status' => '470', 'statusDescription' => 'Invalid or missing token']);
        return;
    }

    $ins = $conn->prepare(
        'INSERT INTO bookings (passenger, flight, status) VALUES (:p, :f, "OK")'
    );
    $ins->bindValue(':p', $user['id'], PDO::PARAM_INT);  // bound to the token's owner
    $ins->bindValue(':f', $flight,     PDO::PARAM_INT);
    echo json_encode($ins->execute()
        ? ['status' => '200', 'statusDescription' => 'OK']
        : ['status' => '460', 'statusDescription' => 'Booking failed']);
}

function respond($rows) {
    array_unshift($rows, ['status' => '200', 'statusDescription' => 'Ok']);
    echo json_encode($rows);
}

function methodNotAllowed() {
    http_response_code(405);
    echo json_encode(['status' => '405', 'statusDescription' => 'Method not allowed']);
}
