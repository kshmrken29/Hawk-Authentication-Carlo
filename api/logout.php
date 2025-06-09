<?php
// Include necessary files
require_once '../config/database.php';
require_once '../utils/functions.php';

// Set headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Access-Control-Allow-Headers, Content-Type, Authorization, X-CSRF-Token');

// Handle OPTIONS request for CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Check if request method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('error', 'Only POST method is allowed');
}

// Extract Hawk ID from Authorization header
$hawk_id = extractHawkIdFromHeader();

if (!$hawk_id) {
    sendResponse('error', 'Invalid Hawk authentication');
}

// Create database connection
$database = new Database();
$conn = $database->getConnection();

// Check if the user is already logged out
$check_stmt = $conn->prepare("SELECT id FROM revoked_tokens WHERE hawk_id = ?");
$check_stmt->bind_param("s", $hawk_id);
$check_stmt->execute();
$check_result = $check_stmt->get_result();

// If the Hawk ID is already in the revoked_tokens table, the user is already logged out
if ($check_result->num_rows > 0) {
    sendResponse('error', 'User already logged out');
}
$check_stmt->close();

// Verify Hawk authentication
$user_id = verifyHawkAuthentication();

if (!$user_id) {
    sendResponse('error', 'Invalid Hawk authentication');
}

// Clear login session cookie
setcookie('login_session_' . $user_id, '', time() - 3600, '/');

// Generate new Hawk credentials to invalidate the current session even if someone saved the credentials
$new_hawk_id = generateHawkId();
$new_hawk_key = generateSecureToken();

// Update user with new Hawk credentials
$update_stmt = $conn->prepare("UPDATE users SET hawk_id = ?, hawk_key = ? WHERE id = ?");
$update_stmt->bind_param("ssi", $new_hawk_id, $new_hawk_key, $user_id);
$update_stmt->execute();
$update_stmt->close();

// Revoke the old Hawk ID
if (revokeHawkId($conn, $hawk_id)) {
    sendResponse('success', 'Logged out successfully');
} else {
    sendResponse('error', 'Failed to logout');
}

// Close connection
$conn->close();
?> 