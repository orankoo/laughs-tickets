<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'laughs_and_tickets');

// Create database connection
function getDBConnection() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        // Log the error for debugging
        error_log("Database connection failed: " . $conn->connect_error);
        
        // Return a generic error message for production
        http_response_code(500);
        die(json_encode([
            'status' => 500,
            'error' => 'Internal server error'
        ]));
    }
    
    return $conn;
}

function jsonResponse($statusCode, $data = null, $error = null) {
    http_response_code($statusCode);
    echo json_encode([
        'status' => $statusCode,
        'data' => $data,
        'error' => $error
    ]);
    exit;
}
?>