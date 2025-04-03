<?php
require_once 'config.php';
require_once 'vendor/autoload.php'; // For JWT library

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
    default:
        jsonResponse(404, null, 'Endpoint not found');
}

// Close database connection
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
            jsonResponse(405, null, 'Method not allowed');
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
                jsonResponse(404, null, 'Action not found');
            }
            break;
        default:
            jsonResponse(405, null, 'Method not allowed');
    }
}

function handleBookingsRequest($method, $path, $conn) {
    // Verify JWT token
    $headers = getallheaders();
    $token = str_replace('Bearer ', '', $headers['Authorization'] ?? '');
    $decoded = validateJWT($token);
    
    if (!$decoded) {
        jsonResponse(401, null, 'Unauthorized');
    }
    
    $userId = $decoded->userId;
    $bookingId = $path[2] ?? null;
    
    switch ($method) {
        case 'GET':
            listUserBookings($conn, $userId);
            break;
        case 'POST':
            createBooking($conn, $userId);
            break;
        default:
            jsonResponse(405, null, 'Method not allowed');
    }
}

// ===== Specific Endpoint Functions =====

function listEvents($conn) {
    // Get query parameters
    $location = $_GET['location'] ?? null;
    $date = $_GET['date'] ?? null;
    $search = $_GET['search'] ?? null;
    
    // Build SQL query
    $sql = "SELECT * FROM events WHERE 1=1";
    $params = [];
    $types = '';
    
    if ($location) {
        $sql .= " AND location LIKE ?";
        $params[] = "%$location%";
        $types .= 's';
    }
    
    if ($date) {
        $sql .= " AND DATE(event_date) = ?";
        $params[] = $date;
        $types .= 's';
    }
    
    if ($search) {
        $sql .= " AND (title LIKE ? OR description LIKE ? OR venue LIKE ?)";
        $params[] = "%$search%";
        $params[] = "%$search%";
        $params[] = "%$search%";
        $types .= 'sss';
    }
    
    $sql .= " ORDER BY event_date ASC";
    
    // Prepare and execute
    $stmt = $conn->prepare($sql);
    
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
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
    // Get event details
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
    // Get input data
    $data = json_decode(file_get_contents('php://input'), true);
    
    $fullName = $data['full_name'] ?? '';
    $email = $data['email'] ?? '';
    $phone = $data['phone'] ?? '';
    $password = $data['password'] ?? '';
    $confirmPassword = $data['confirm_password'] ?? '';
    
    // Validate input
    if (empty($fullName) || empty($email) || empty($password) || empty($confirmPassword)) {
        jsonResponse(400, null, 'All fields are required');
    }
    
    if ($password !== $confirmPassword) {
        jsonResponse(400, null, 'Passwords do not match');
    }
    
    if (strlen($password) < 8) {
        jsonResponse(400, null, 'Password must be at least 8 characters');
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        jsonResponse(400, null, 'Invalid email format');
    }
    
    // Check if user exists
    $stmt = $conn->prepare("SELECT user_id FROM users WHERE email = ?");
    $stmt->bind_param('s', $email);
    $stmt->execute();
    
    if ($stmt->get_result()->num_rows > 0) {
        jsonResponse(400, null, 'Email already registered');
    }
    
    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
    
    // Create user
    $stmt = $conn->prepare("
        INSERT INTO users (full_name, email, phone, password) 
        VALUES (?, ?, ?, ?)
    ");
    $stmt->bind_param('ssss', $fullName, $email, $phone, $hashedPassword);
    
    if ($stmt->execute()) {
        $userId = $conn->insert_id;
        $token = generateJWT($userId, $email);
        
        jsonResponse(201, [
            'token' => $token,
            'user' => [
                'id' => $userId,
                'name' => $fullName,
                'email' => $email,
                'phone' => $phone
            ]
        ]);
    } else {
        jsonResponse(500, null, 'Failed to register user');
    }
}

function loginUser($conn) {
    // Get input data
    $data = json_decode(file_get_contents('php://input'), true);
    
    $email = $data['email'] ?? '';
    $password = $data['password'] ?? '';
    
    // Validate input
    if (empty($email) || empty($password)) {
        jsonResponse(400, null, 'Email and password are required');
    }
    
    // Get user
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    
    if (!$user || !password_verify($password, $user['password'])) {
        jsonResponse(401, null, 'Invalid email or password');
    }
    
    // Generate token
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
    
    $eventId = $data['event_id'] ?? 0;
    $ticketId = $data['ticket_id'] ?? 0;
    $quantity = $data['quantity'] ?? 0;
    
    // Validate input
    if ($eventId <= 0 || $ticketId <= 0 || $quantity <= 0) {
        jsonResponse(400, null, 'Invalid booking details');
    }
    
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
        $ticketStmt->bind_param('ii', $ticketId, $eventId);
        $ticketStmt->execute();
        $ticket = $ticketStmt->get_result()->fetch_assoc();
        
        if (!$ticket) {
            throw new Exception('Ticket not found');
        }
        
        if ($ticket['quantity_available'] < $quantity) {
            throw new Exception('Not enough tickets available');
        }
        
        // Calculate total amount
        $totalAmount = $ticket['price'] * $quantity;
        
        // Create booking
        $bookingStmt = $conn->prepare("
            INSERT INTO bookings (user_id, event_id, ticket_id, quantity, total_amount)
            VALUES (?, ?, ?, ?, ?)
        ");
        $bookingStmt->bind_param('iiiid', $userId, $eventId, $ticketId, $quantity, $totalAmount);
        $bookingStmt->execute();
        
        $bookingId = $conn->insert_id;
        
        // Update ticket availability
        $updateStmt = $conn->prepare("
            UPDATE tickets 
            SET quantity_available = quantity_available - ? 
            WHERE ticket_id = ?
        ");
        $updateStmt->bind_param('ii', $quantity, $ticketId);
        $updateStmt->execute();
        
        $conn->commit();
        
        jsonResponse(201, [
            'booking_id' => $bookingId,
            'message' => 'Booking created successfully'
        ]);
    } catch (Exception $e) {
        $conn->rollback();
        jsonResponse(400, null, $e->getMessage());
    }
}
?>