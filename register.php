<?php
include 'config.php'; // Database connection

// Get form data
$name = $_POST['name'];
$email = $_POST['email'];
$phone = $_POST['phone']; 
$password = $_POST['password'];
$confirm_password = $_POST['confirm_password']; 

// Validate confirm password
if ($password !== $confirm_password) {
    die("Error: Passwords do not match.");
}

// Encrypt password
$hashed_password = password_hash($password, PASSWORD_DEFAULT);

// Use prepared statements for secure database insertion
$stmt = $conn->prepare("INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)");
$stmt->bind_param("ssss", $name, $email, $phone, $hashed_password);
$stmt->execute();
$stmt->close();

echo "Registration successful!";

$conn->close();
?>