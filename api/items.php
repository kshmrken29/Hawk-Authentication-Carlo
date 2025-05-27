<?php
// Include necessary files
require_once '../config/database.php';
require_once '../utils/functions.php';

// Set headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Access-Control-Allow-Headers, Content-Type, Authorization, X-CSRF-Token');

// Handle OPTIONS request for CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Get request method
$method = getRequestMethod();

// Create database connection
$database = new Database();
$conn = $database->getConnection();

// Get request data
$data = getRequestData();

// Check Hawk authentication for all methods
$user_id = verifyHawkAuthentication();

if (!$user_id) {
    sendResponse('error', 'Invalid Hawk authentication. Please login first.');
}

// Handle different request methods
switch ($method) {
    case 'GET':
        // Get single item or all items
        if (isset($_GET['id'])) {
            // Get single item
            $id = $_GET['id'];
            
            $stmt = $conn->prepare("SELECT * FROM items WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $item = $result->fetch_assoc();
                sendResponse('success', 'Item found', $item);
            } else {
                sendResponse('error', 'Item not found');
            }
        } else {
            // Get all items
            $stmt = $conn->prepare("SELECT * FROM items");
            $stmt->execute();
            $result = $stmt->get_result();
            
            $items = [];
            while ($row = $result->fetch_assoc()) {
                $items[] = $row;
            }
            
            sendResponse('success', 'Items retrieved successfully', $items);
        }
        break;
        
    case 'POST':
        // Create new item
        $required_fields = ['name', 'description', 'price'];
        if (!checkRequiredFields($required_fields, $data)) {
            sendResponse('error', 'Please fill all required fields');
        }
        
        $name = $data['name'];
        $description = $data['description'];
        $price = $data['price'];
        
        $stmt = $conn->prepare("INSERT INTO items (name, description, price, user_id) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssdi", $name, $description, $price, $user_id);
        
        if ($stmt->execute()) {
            $item_id = $stmt->insert_id;
            sendResponse('success', 'Item created successfully', ['id' => $item_id]);
        } else {
            sendResponse('error', 'Failed to create item: ' . $conn->error);
        }
        break;
        
    case 'PUT':
        // Update item
        if (!isset($_GET['id'])) {
            sendResponse('error', 'Item ID is required');
        }
        
        $id = $_GET['id'];
        
        // Check if item exists and belongs to the user
        $stmt = $conn->prepare("SELECT user_id FROM items WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            sendResponse('error', 'Item not found');
        }
        
        $item = $result->fetch_assoc();
        
        if ($item['user_id'] != $user_id) {
            sendResponse('error', 'You do not have permission to update this item');
        }
        
        // Update item
        $fields = [];
        $types = '';
        $values = [];
        
        if (isset($data['name']) && !empty($data['name'])) {
            $fields[] = 'name = ?';
            $types .= 's';
            $values[] = $data['name'];
        }
        
        if (isset($data['description']) && !empty($data['description'])) {
            $fields[] = 'description = ?';
            $types .= 's';
            $values[] = $data['description'];
        }
        
        if (isset($data['price']) && !empty($data['price'])) {
            $fields[] = 'price = ?';
            $types .= 'd';
            $values[] = $data['price'];
        }
        
        if (empty($fields)) {
            sendResponse('error', 'No fields to update');
        }
        
        $sql = "UPDATE items SET " . implode(', ', $fields) . " WHERE id = ?";
        $types .= 'i';
        $values[] = $id;
        
        $stmt = $conn->prepare($sql);
        $stmt->bind_param($types, ...$values);
        
        if ($stmt->execute()) {
            sendResponse('success', 'Item updated successfully');
        } else {
            sendResponse('error', 'Failed to update item: ' . $conn->error);
        }
        break;
        
    case 'DELETE':
        // Delete item
        if (!isset($_GET['id'])) {
            sendResponse('error', 'Item ID is required');
        }
        
        $id = $_GET['id'];
        
        // Check if item exists and belongs to the user
        $stmt = $conn->prepare("SELECT user_id FROM items WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            sendResponse('error', 'Item not found');
        }
        
        $item = $result->fetch_assoc();
        
        if ($item['user_id'] != $user_id) {
            sendResponse('error', 'You do not have permission to delete this item');
        }
        
        // Delete item
        $stmt = $conn->prepare("DELETE FROM items WHERE id = ?");
        $stmt->bind_param("i", $id);
        
        if ($stmt->execute()) {
            sendResponse('success', 'Item deleted successfully');
        } else {
            sendResponse('error', 'Failed to delete item: ' . $conn->error);
        }
        break;
        
    default:
        sendResponse('error', 'Invalid request method');
}

// Close connection
$conn->close();
?> 