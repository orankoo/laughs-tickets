<?php
include 'config.php';
session_start();

$event_id = $_POST['event_id'];
$user_id = $_SESSION['user_id'];
$user_name = $_SESSION['user_name'];
$rating = $_POST['rating'];
$comment = $_POST['comment'];

$sql = "INSERT INTO reviews (event_id, user_id, user_name, rating, comment) 
        VALUES ('$event_id', '$user_id', '$user_name', '$rating', '$comment')";

if ($conn->query($sql) === TRUE) {
    echo "Review submitted!";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

$conn->close();
?>