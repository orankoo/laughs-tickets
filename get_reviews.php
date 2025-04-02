<?php
include 'config.php';

$event_id = $_GET['event_id'];
$sql = "SELECT * FROM reviews WHERE event_id='$event_id'";
$result = $conn->query($sql);

$reviews = array();
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $reviews[] = $row;
    }
    echo json_encode($reviews); // Output as JSON for frontend
} else {
    echo "No reviews yet.";
}

$conn->close();
?>