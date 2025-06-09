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
$required_fields = ['username', 'password'];
if (!checkRequiredFields($required_fields, $data)) {
    sendResponse('error', 'Please provide username and password');
}

// Extract data
$username = $data['username'];
$password = $data['password'];

// Create database connection
$database = new Database();
$conn = $database->getConnection();

// Check if user exists
$stmt = $conn->prepare("SELECT id, username, password, hawk_id, hawk_key, hawk_algorithm FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    sendResponse('error', 'User not found');
}

$user = $result->fetch_assoc();

// Verify password
if (!password_verify($password, $user['password'])) {
    sendResponse('error', 'Invalid password');
}

// Check if the user's current Hawk ID is NOT in revoked_tokens
// This is the simple way to check if they're already logged in
$check_stmt = $conn->prepare("SELECT id FROM revoked_tokens WHERE hawk_id = ?");
$check_stmt->bind_param("s", $user['hawk_id']);
$check_stmt->execute();
$check_result = $check_stmt->get_result();
$check_stmt->close();

// If the Hawk ID is not in the revoked_tokens table, the user is already logged in
if ($check_result->num_rows === 0 && !empty($_COOKIE['login_session_' . $user['id']])) {
    sendResponse('error', 'User already logged in. Please logout first before logging in again.', [
        'id' => $user['id'],
        'username' => $user['username'],
        'hawk_id' => $user['hawk_id'],
        'hawk_key' => $user['hawk_key'],
        'hawk_algorithm' => $user['hawk_algorithm']
    ]);
}

// Generate new Hawk credentials
$new_hawk_id = generateHawkId();
$new_hawk_key = generateSecureToken();
$algorithm = 'sha256';

// Update user with new Hawk credentials
$update_stmt = $conn->prepare("UPDATE users SET hawk_id = ?, hawk_key = ? WHERE id = ?");
$update_stmt->bind_param("ssi", $new_hawk_id, $new_hawk_key, $user['id']);
$update_stmt->execute();
$update_stmt->close();

// Set a cookie to track login session
setcookie('login_session_' . $user['id'], '1', time() + 86400, '/'); 

// Send response with new Hawk credentials
sendResponse('success', 'Login successful', [
    'id' => $user['id'],
    'username' => $user['username'],
    'hawk_id' => $new_hawk_id,
    'hawk_key' => $new_hawk_key,
    'hawk_algorithm' => $algorithm
]);

// Close connection
$stmt->close();
$conn->close();
?> 