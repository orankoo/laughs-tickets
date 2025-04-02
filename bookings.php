<?php
include 'config.php';

$event_id = 101;
$user_id = 1;
$seats = "A12, A13";
$total = 3000;
$expires_at = date('Y-m-d H:i:s', strtotime('+15 minutes'));

$sql = "INSERT INTO bookings (event_id, user_id, seats, total, expires_at, status) 
        VALUES ('$event_id', '$user_id', '$seats', '$total', '$expires_at', 'pending')";

if ($conn->query($sql) === TRUE) {
    echo "Booking held! Complete payment within 15 minutes.";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

$conn->close();
?>