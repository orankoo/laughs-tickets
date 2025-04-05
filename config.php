<?php
require_once __DIR__ . '/vendor/autoload.php'; // Include Composer autoloader

use Firebase\JWT\JWT;
use Firebase\JWT\Key; // Import the Key class for decoding JWTs
use Firebase\JWT\ExpiredException; // Import the ExpiredException class

// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'laughs_and_tickets' );
define('JWT_SECRET', 'your_very_secure_jwt_secret_here');

// Create database connection
function getDBConnection() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        http_response_code(500);
        die("Connection failed: " . $conn->connect_error);
    }
    
    return $conn;
}

// JSON response helper
function jsonResponse($status, $data = null, $error = null) {
    header('Content-Type: application/json');
    http_response_code($status);
    
    $response = [
        'status' => $status < 400 ? 'success' : 'error',
        'data' => $data,
        'error' => $error
    ];
    
    echo json_encode($response);
    exit;
}

// Generate JWT token
function generateJWT($userId, $email) {
    $issuedAt = time();
    $expirationTime = $issuedAt + 86400; // 24 hours
    
    $payload = [
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'userId' => $userId,
        'email' => $email
    ];
    
    return JWT::encode($payload, JWT_SECRET, 'HS256');
}

// Middleware to check if the request has a valid JWT token
function authenticate() {
    if (!function_exists('getallheaders')) {
        function getallheaders() {
            $headers = [];
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_') {
                    $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
                }
            }
            return $headers;
        }
    }
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        jsonResponse(401, null, 'Authorization header missing');
    }

    $authHeader = $headers['Authorization'];
    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        jsonResponse(401, null, 'Invalid Authorization header format');
    }

    $token = $matches[1];
    $decoded = validateJWT($token);
    if (!$decoded) {
        jsonResponse(401, null, 'Invalid or expired token');
    }

    return $decoded;
}

// Validate JWT token
function validateJWT($token) {
    try {
        // Use the Key class to pass the secret key and algorithm
        return JWT::decode($token, new Key(JWT_SECRET, 'HS256'));
    } catch (\Firebase\JWT\ExpiredException $e) {
        jsonResponse(401, null, 'Token has expired');
    } catch (\Firebase\JWT\SignatureInvalidException $e) {
        jsonResponse(401, null, 'Invalid token signature');
    } catch (\Exception $e) {
        jsonResponse(401, null, 'Invalid token');
    }
}
