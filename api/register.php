<?php
// Include necessary files
require_once '../config/database.php';
require_once '../utils/functions.php';

// Set headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Access-Control-Allow-Headers, Content-Type, Authorization, X-CSRF-Token');

// Check if request method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('error', 'Only POST method is allowed');
}

// Get request data
$data = getRequestData();

// Check required fields
$required_fields = ['username', 'email', 'password'];
if (!checkRequiredFields($required_fields, $data)) {
    sendResponse('error', 'Please fill all required fields');
}

// Extract data
$username = $data['username'];
$email = $data['email'];
$password = $data['password'];

// Create database connection
$database = new Database();
$conn = $database->getConnection();

// Check if username already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    sendResponse('error', 'Username already exists. Please choose a different username.');
}

// Check if email already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    sendResponse('error', 'Email already registered. Please use a different email address.');
}

// Hash password
$hashed_password = password_hash($password, PASSWORD_DEFAULT);

// Generate Hawk credentials
$hawk_id = generateHawkId();
$hawk_key = generateSecureToken(32);
$hawk_algorithm = 'sha256';

// Insert user
$stmt = $conn->prepare("INSERT INTO users (username, email, password, hawk_id, hawk_key, hawk_algorithm) VALUES (?, ?, ?, ?, ?, ?)");
$stmt->bind_param("ssssss", $username, $email, $hashed_password, $hawk_id, $hawk_key, $hawk_algorithm);

if ($stmt->execute()) {
    $user_id = $stmt->insert_id;
    sendResponse('success', 'User registered successfully', [
        'id' => $user_id, 
        'username' => $username, 
        'hawk_id' => $hawk_id,
        'hawk_key' => $hawk_key,
        'hawk_algorithm' => $hawk_algorithm
    ]);
} else {
    sendResponse('error', 'Failed to register user: ' . $conn->error);
}

// Close connection
$stmt->close();
$conn->close();
?> 