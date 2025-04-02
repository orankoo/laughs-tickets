<?php
include 'config.php';

$event_id = $_POST['event_id'];
$user_id = $_POST['user_id'];
$seat_number = $_POST['seat_number'];
$price = $_POST['price'];
$qr_code_url = "qr_" . bin2hex(random_bytes(3)) . ".png"; // Generate fake QR code URL

$sql = "INSERT INTO tickets (event_id, user_id, seat_number, price, qr_code_url, status) 
        VALUES ('$event_id', '$user_id', '$seat_number', '$price', '$qr_code_url', 'active')";

if ($conn->query($sql) === TRUE) {
    echo "Ticket generated!";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

$conn->close();
?>