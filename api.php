<?php
require_once 'config.php';
require_once 'vendor/autoload.php';

// Handle CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

// Handle preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = explode('/', trim($path, '/'));

// Main API endpoint
$endpoint = $path[1] ?? '';

// Connect to database
$conn = getDBConnection();

// Route the request
switch ($endpoint) {
    case 'events':
        handleEventsRequest($method, $path, $conn);
        break;
    case 'auth':
        handleAuthRequest($method, $path, $conn);
        break;
    case 'bookings':
        handleBookingsRequest($method, $path, $conn);
        break;
    case 'reviews':
        handleReviewsRequest($method, $path, $conn);
        break;
    default:
        jsonResponse(404, ['message' => 'Endpoint not found']);
}

$conn->close();

// ===== Request Handlers =====

function handleEventsRequest($method, $path, $conn) {
    $eventId = $path[2] ?? null;
    
    switch ($method) {
        case 'GET':
            if ($eventId) {
                getEvent($conn, $eventId);
            } else {
                listEvents($conn);
            }
            break;
        default:
            jsonResponse(405, ['message' => 'Method not allowed']);
    }
}

function handleAuthRequest($method, $path, $conn) {
    $action = $path[2] ?? '';
    
    switch ($method) {
        case 'POST':
            if ($action === 'login') {
                loginUser($conn);
            } elseif ($action === 'register') {
                registerUser($conn);
            } else {
                jsonResponse(404, ['message' => 'Action not found']);
            }
            break;
        default:
            jsonResponse(405, ['message' => 'Method not allowed']);
    }
}

function handleBookingsRequest($method, $path, $conn) {
    $token = getBearerToken();
    $decoded = validateJWT($token) or jsonResponse(401, ['message' => 'Unauthorized']);
    $userId = $decoded->userId;

    switch ($method) {
        case 'GET':
            listUserBookings($conn, $userId);
            break;
        case 'POST':
            createBooking($conn, $userId);
            break;
        default:
            jsonResponse(405, ['message' => 'Method not allowed']);
    }
}

function handleReviewsRequest($method, $path, $conn) {
    if ($method !== 'GET') {
        $token = getBearerToken();
        $decoded = validateJWT($token) or jsonResponse(401, ['message' => 'Unauthorized']);
        $userId = $decoded->userId;
    }

    $eventId = $path[2] ?? null;

    switch ($method) {
        case 'GET':
            if ($eventId) {
                getEventReviews($conn, $eventId);
            } else {
                jsonResponse(400, ['message' => 'Event ID required']);
            }
            break;
        case 'POST':
            submitReview($conn, $userId);
            break;
        default:
            jsonResponse(405, ['message' => 'Method not allowed']);
    }
}

// ===== Helper Functions =====

function getBearerToken() {
    $headers = getallheaders();
    return str_replace('Bearer ', '', $headers['Authorization'] ?? '');
}

function jsonResponse($code, $data = null, $message = null) {
    http_response_code($code);
    header('Content-Type: application/json');
    exit(json_encode([
        'status' => $code < 400 ? 'success' : 'error',
        'data' => $data,
        'message' => $message ?? ($code < 400 ? 'Operation successful' : 'An error occurred')
    ]));
}

// ===== Core Functions =====

function listEvents($conn) {
    // Get query parameters
    $params = [
        'location' => $_GET['location'] ?? null,
        'date' => $_GET['date'] ?? null,
        'search' => $_GET['search'] ?? null
    ];

    // Build SQL query
    $sql = "SELECT * FROM events WHERE 1=1";
    $bindParams = [];
    $types = '';
    
    if ($params['location']) {
        $sql .= " AND location LIKE ?";
        $bindParams[] = "%{$params['location']}%";
        $types .= 's';
    }
    
    if ($params['date']) {
        $sql .= " AND DATE(event_date) = ?";
        $bindParams[] = $params['date'];
        $types .= 's';
    }
    
    if ($params['search']) {
        $sql .= " AND (title LIKE ? OR description LIKE ? OR venue LIKE ?)";
        $bindParams[] = "%{$params['search']}%";
        $bindParams[] = "%{$params['search']}%";
        $bindParams[] = "%{$params['search']}%";
        $types .= 'sss';
    }
    
    $sql .= " ORDER BY event_date ASC";
    
    $stmt = $conn->prepare($sql);
    if (!empty($bindParams)) {
        $stmt->bind_param($types, ...$bindParams);
    }
    
    $stmt->execute();
    $result = $stmt->get_result();
    
    $events = [];
    while ($row = $result->fetch_assoc()) {
        // Get tickets for each event
        $ticketStmt = $conn->prepare("SELECT * FROM tickets WHERE event_id = ?");
        $ticketStmt->bind_param('i', $row['event_id']);
        $ticketStmt->execute();
        $tickets = $ticketStmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        $row['tickets'] = $tickets;
        $events[] = $row;
    }
    
    jsonResponse(200, $events);
}

function getEvent($conn, $eventId) {
    $stmt = $conn->prepare("SELECT * FROM events WHERE event_id = ?");
    $stmt->bind_param('i', $eventId);
    $stmt->execute();
    $event = $stmt->get_result()->fetch_assoc();
    
    if (!$event) {
        jsonResponse(404, null, 'Event not found');
    }
    
    // Get tickets
    $ticketStmt = $conn->prepare("SELECT * FROM tickets WHERE event_id = ?");
    $ticketStmt->bind_param('i', $eventId);
    $ticketStmt->execute();
    $event['tickets'] = $ticketStmt->get_result()->fetch_all(MYSQLI_ASSOC);
    
    // Get reviews
    $reviewStmt = $conn->prepare("
        SELECT r.*, u.full_name 
        FROM reviews r
        JOIN users u ON r.user_id = u.user_id
        WHERE r.event_id = ?
        ORDER BY r.created_at DESC
    ");
    $reviewStmt->bind_param('i', $eventId);
    $reviewStmt->execute();
    $event['reviews'] = $reviewStmt->get_result()->fetch_all(MYSQLI_ASSOC);
    
    jsonResponse(200, $event);
}

function registerUser($conn) {
    $data = json_decode(file_get_contents('php://input'), true) or jsonResponse(400, null, 'Invalid JSON');
    
    $required = ['full_name', 'email', 'phone', 'password', 'confirm_password'];
    foreach ($required as $field) {
        if (empty($data[$field])) {
            jsonResponse(400, null, "$field is required");
        }
    }
    
    if ($data['password'] !== $data['confirm_password']) {
        jsonResponse(400, null, 'Passwords do not match');
    }
    
    if (strlen($data['password']) < 8) {
        jsonResponse(400, null, 'Password must be at least 8 characters');
    }
    
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        jsonResponse(400, null, 'Invalid email format');
    }
    
    // Check if user exists
    $stmt = $conn->prepare("SELECT user_id FROM users WHERE email = ?");
    $stmt->bind_param('s', $data['email']);
    $stmt->execute();
    
    if ($stmt->get_result()->num_rows > 0) {
        jsonResponse(400, null, 'Email already registered');
    }
    
    // Hash password
    $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
    
    // Create user
    $stmt = $conn->prepare("INSERT INTO users (full_name, email, phone, password) VALUES (?, ?, ?, ?)");
    $stmt->bind_param('ssss', $data['full_name'], $data['email'], $data['phone'], $hashedPassword);
    
    if ($stmt->execute()) {
        $userId = $conn->insert_id;
        $token = generateJWT($userId, $data['email']);
        
        jsonResponse(201, [
            'token' => $token,
            'user' => [
                'id' => $userId,
                'name' => $data['full_name'],
                'email' => $data['email'],
                'phone' => $data['phone']
            ]
        ]);
    } else {
        jsonResponse(500, null, 'Failed to register user');
    }
}

function loginUser($conn) {
    $data = json_decode(file_get_contents('php://input'), true) or jsonResponse(400, null, 'Invalid JSON');
    
    if (empty($data['email']) || empty($data['password'])) {
        jsonResponse(400, null, 'Email and password are required');
    }
    
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param('s', $data['email']);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    
    if (!$user || !password_verify($data['password'], $user['password'])) {
        jsonResponse(401, null, 'Invalid email or password');
    }
    
    $token = generateJWT($user['user_id'], $user['email']);
    
    jsonResponse(200, [
        'token' => $token,
        'user' => [
            'id' => $user['user_id'],
            'name' => $user['full_name'],
            'email' => $user['email'],
            'phone' => $user['phone']
        ]
    ]);
}

function listUserBookings($conn, $userId) {
    $stmt = $conn->prepare("
        SELECT b.*, e.title AS event_title, e.event_date, e.venue, 
               t.ticket_type, t.price, e.image_url
        FROM bookings b
        JOIN events e ON b.event_id = e.event_id
        JOIN tickets t ON b.ticket_id = t.ticket_id
        WHERE b.user_id = ?
        ORDER BY b.booking_date DESC
    ");
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $bookings = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    
    jsonResponse(200, $bookings);
}
function createBooking($conn, $userId) {
    // Get input data
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validate basic input
    if (empty($data['event_id']) || empty($data['ticket_id']) || empty($data['quantity'])) {
        jsonResponse(400, null, 'Event ID, ticket ID and quantity are required');
    }

    // Set default values for optional fields
    $seats = $data['seats'] ?? null;
    $status = $data['status'] ?? 'pending'; // Default to pending like in your example
    $expiresAt = isset($data['hold_for_minutes']) ? 
        date('Y-m-d H:i:s', strtotime('+' . (int)$data['hold_for_minutes'] . ' minutes')) : 
        null;

    // Check ticket availability
    $conn->begin_transaction();
    
    try {
        // Get ticket details with FOR UPDATE to lock the row
        $ticketStmt = $conn->prepare("
            SELECT price, quantity_available 
            FROM tickets 
            WHERE ticket_id = ? AND event_id = ?
            FOR UPDATE
        ");
        $ticketStmt->bind_param('ii', $data['ticket_id'], $data['event_id']);
        $ticketStmt->execute();
        $ticket = $ticketStmt->get_result()->fetch_assoc();
        
        if (!$ticket) {
            throw new Exception('Ticket not found');
        }
        
        if ($ticket['quantity_available'] < $data['quantity']) {
            throw new Exception('Not enough tickets available');
        }
        
        // Calculate total amount (allow override from client if needed)
        $totalAmount = $data['total'] ?? ($ticket['price'] * $data['quantity']);

        // Create booking with all fields
        $bookingStmt = $conn->prepare("
            INSERT INTO bookings (
                user_id, 
                event_id, 
                ticket_id, 
                quantity, 
                seats, 
                total_amount, 
                expires_at, 
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $bookingStmt->bind_param(
            'iiiisdss',
            $userId,
            $data['event_id'],
            $data['ticket_id'],
            $data['quantity'],
            $seats,
            $totalAmount,
            $expiresAt,
            $status
        );
        
        $bookingStmt->execute();
        
        // Update ticket availability
        $updateStmt = $conn->prepare("
            UPDATE tickets 
            SET quantity_available = quantity_available - ? 
            WHERE ticket_id = ?
        ");
        $updateStmt->bind_param('ii', $data['quantity'], $data['ticket_id']);
        $updateStmt->execute();
        
        $conn->commit();
        
        jsonResponse(201, [
            'booking_id' => $conn->insert_id,
            'seats' => $seats,
            'total' => $totalAmount,
            'expires_at' => $expiresAt,
            'status' => $status,
            'message' => $status === 'pending' ? 
                'Booking held! Complete payment within ' . ($data['hold_for_minutes'] ?? 15) . ' minutes.' : 
                'Booking confirmed successfully'
        ]);
    } catch (Exception $e) {
        $conn->rollback();
        jsonResponse(400, null, $e->getMessage());
    }
}


function getEventReviews($conn, $eventId) {
    $stmt = $conn->prepare("
        SELECT r.*, u.full_name 
        FROM reviews r
        JOIN users u ON r.user_id = u.user_id
        WHERE r.event_id = ?
        ORDER BY r.created_at DESC
    ");
    $stmt->bind_param('i', $eventId);
    $stmt->execute();
    $reviews = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    
    jsonResponse(200, $reviews);
}

function submitReview($conn, $userId) {
    $data = json_decode(file_get_contents('php://input'), true) or jsonResponse(400, null, 'Invalid JSON');
    
    if (empty($data['event_id']) || empty($data['rating']) || !isset($data['comment'])) {
        jsonResponse(400, null, 'Missing review data');
    }
    
    if ($data['rating'] < 1 || $data['rating'] > 5) {
        jsonResponse(400, null, 'Rating must be between 1 and 5');
    }
    
    $stmt = $conn->prepare("
        INSERT INTO reviews (user_id, event_id, rating, comment)
        VALUES (?, ?, ?, ?)
    ");
    $stmt->bind_param('iiis', $userId, $data['event_id'], $data['rating'], $data['comment']);
    
    if ($stmt->execute()) {
        jsonResponse(201, [
            'review_id' => $conn->insert_id,
            'message' => 'Review submitted successfully'
        ]);
    } else {
        jsonResponse(500, null, 'Failed to submit review');
    }
}
?>