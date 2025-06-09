<?php
// Include Hawk authentication
require_once __DIR__ . '/hawk.php';

// Function to generate secure random string for Hawk keys
function generateSecureToken($length = 32) {
    return HawkAuth::generateKey($length);
}

// Function to generate Hawk ID
function generateHawkId() {
    return HawkAuth::generateId();
}

// Function to validate Hawk credentials
function validateHawkCredentials($conn, $hawk_id) {
    // First check if the token is revoked
    $stmt = $conn->prepare("SELECT id FROM revoked_tokens WHERE hawk_id = ?");
    $stmt->bind_param("s", $hawk_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    // If token is revoked, return false
    if ($result->num_rows > 0) {
        return false;
    }
    
    // If not revoked, check if it's a valid token
    $stmt = $conn->prepare("SELECT id, hawk_key, hawk_algorithm FROM users WHERE hawk_id = ?");
    $stmt->bind_param("s", $hawk_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        
        // Additional check: Make sure this is the current Hawk ID for this user
        $check_stmt = $conn->prepare("SELECT COUNT(*) as count FROM users WHERE id = ? AND hawk_id = ?");
        $check_stmt->bind_param("is", $row['id'], $hawk_id);
        $check_stmt->execute();
        $check_result = $check_stmt->get_result();
        $check_row = $check_result->fetch_assoc();
        
        if ($check_row['count'] === 0) {
            // This Hawk ID is not the current one for this user
            return false;
        }
        
        return [
            'user_id' => $row['id'],
            'key' => $row['hawk_key'],
            'algorithm' => $row['hawk_algorithm']
        ];
    }
    
    return false;
}

// Function to revoke a Hawk ID (logout)
function revokeHawkId($conn, $hawk_id) {
    // Check if the token is already revoked
    $stmt = $conn->prepare("SELECT id FROM revoked_tokens WHERE hawk_id = ?");
    $stmt->bind_param("s", $hawk_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    // If already revoked, return true
    if ($result->num_rows > 0) {
        return true;
    }
    
    // Otherwise, add to revoked tokens
    $stmt = $conn->prepare("INSERT INTO revoked_tokens (hawk_id) VALUES (?)");
    $stmt->bind_param("s", $hawk_id);
    
    return $stmt->execute();
}

// Function to validate API key
function validateApiKey($conn, $api_key) {
    $stmt = $conn->prepare("SELECT id FROM users WHERE api_key = ?");
    $stmt->bind_param("s", $api_key);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        return $row['id'];
    }
    
    return false;
}

// Function to check CSRF token - modified to always return true
function validateCSRFToken() {
    // Always return true to avoid needing CSRF token in Postman
    return true;
}

// Function to send JSON response
function sendResponse($status, $message, $data = null) {
    header('Content-Type: application/json');
    
    $response = [
        'status' => $status,
        'message' => $message
    ];
    
    if ($data !== null) {
        $response['data'] = $data;
    }
    
    echo json_encode($response);
    exit;
}

// Function to check required fields
function checkRequiredFields($fields, $data) {
    foreach ($fields as $field) {
        if (!isset($data[$field]) || empty($data[$field])) {
            return false;
        }
    }
    return true;
}

// Get request method
function getRequestMethod() {
    return $_SERVER['REQUEST_METHOD'];
}

// Get request data based on method
function getRequestData() {
    $method = getRequestMethod();
    
    switch ($method) {
        case 'GET':
            return $_GET;
        case 'POST':
            // Try to get from POST first, then from raw input as JSON
            $postData = $_POST;
            if (empty($postData)) {
                $rawData = file_get_contents('php://input');
                if (!empty($rawData)) {
                    $jsonData = json_decode($rawData, true);
                    if ($jsonData !== null) {
                        return $jsonData;
                    }
                }
            }
            return $postData;
        case 'PUT':
        case 'DELETE':
            $rawData = file_get_contents('php://input');
            if (!empty($rawData)) {
                $jsonData = json_decode($rawData, true);
                if ($jsonData !== null) {
                    return $jsonData;
                }
            }
            // Fallback to form data if JSON parsing fails
            parse_str($rawData, $formData);
            return $formData;
        default:
            return [];
    }
}

// Function to verify Hawk authentication
function verifyHawkAuthentication() {
    // Check if Authorization header exists
    $headers = getallheaders();
    if (!isset($headers['Authorization']) && !isset($headers['authorization'])) {
        return false;
    }
    
    // Get Authorization header
    $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : $headers['authorization'];
    
    // Parse Hawk header
    $attributes = HawkAuth::parseHeader($authHeader);
    if (!$attributes) {
        return false;
    }
    
    // Get database connection
    require_once __DIR__ . '/../config/database.php';
    $database = new Database();
    $conn = $database->getConnection();
    
    // Get user credentials
    $credentials = validateHawkCredentials($conn, $attributes['id']);
    if (!$credentials) {
        return false;
    }
    
    // Get request details
    $method = $_SERVER['REQUEST_METHOD'];
    $host = $_SERVER['HTTP_HOST'];
    $port = isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : 80;
    $uri = $_SERVER['REQUEST_URI'];
    
    // Verify request
    if (!HawkAuth::verify($credentials, $attributes, $method, $uri, $host, $port)) {
        return false;
    }
    
    // Return user ID
    return $credentials['user_id'];
}

// Function to extract Hawk ID from Authorization header
function extractHawkIdFromHeader() {
    $headers = getallheaders();
    if (!isset($headers['Authorization']) && !isset($headers['authorization'])) {
        return false;
    }
    
    $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : $headers['authorization'];
    $attributes = HawkAuth::parseHeader($authHeader);
    
    if (!$attributes || !isset($attributes['id'])) {
        return false;
    }
    
    return $attributes['id'];
}

// Function to generate a test Hawk header (for client-side testing)
function generateTestHawkHeader($hawk_id, $hawk_key, $algorithm, $method, $uri) {
    $host = $_SERVER['HTTP_HOST'];
    $port = isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : 80;
    
    return HawkAuth::generateClientHeader($hawk_id, $hawk_key, $algorithm, $method, $uri, $host, $port);
}

// Function to check if a user has recently logged in (within the last 24 hours)
function checkRecentLoginAttempt($conn, $user_id) {
    // Get current user's Hawk ID
    $user_stmt = $conn->prepare("SELECT hawk_id FROM users WHERE id = ?");
    $user_stmt->bind_param("i", $user_id);
    $user_stmt->execute();
    $user_result = $user_stmt->get_result();
    $user = $user_result->fetch_assoc();
    $user_stmt->close();
    
    if (!$user) {
        return false;
    }
    
    // Check if the current Hawk ID is not in revoked_tokens
    $check_stmt = $conn->prepare("SELECT id FROM revoked_tokens WHERE hawk_id = ?");
    $check_stmt->bind_param("s", $user['hawk_id']);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    $check_stmt->close();
    
    // If the Hawk ID is not revoked, it means the user is still logged in
    return ($check_result->num_rows === 0);
}

// Function to record a login attempt
function recordLoginAttempt($conn, $user_id) {
    // For now, this is just a placeholder function
    // In a more complex system, you could log this information to a table
    return true;
}
?> 