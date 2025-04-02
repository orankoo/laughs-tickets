<?php
include 'config.php';

$sql = "SELECT * FROM events"; // Assume you have an `events` table
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        echo "<div class='event'>";
        echo "<h3>" . $row["name"] . "</h3>";
        echo "<p>Price: KSh " . $row["price"] . "</p>";
        echo "</div>";
    }
} else {
    echo "No events found.";
}
$conn->close();
?>