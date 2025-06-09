<?php
// Include necessary files
require_once 'config/database.php';
require_once 'utils/functions.php';
require_once 'utils/hawk.php';

// Set content type
header('Content-Type: text/html');

// Get hawk credentials from query string (for testing only)
$hawk_id = isset($_GET['hawk_id']) ? $_GET['hawk_id'] : '';
$hawk_key = isset($_GET['hawk_key']) ? $_GET['hawk_key'] : '';
$algorithm = isset($_GET['algorithm']) ? $_GET['algorithm'] : 'sha256';

// Generate test header if credentials are provided
$test_header = '';
if (!empty($hawk_id) && !empty($hawk_key)) {
    $test_header = generateTestHawkHeader($hawk_id, $hawk_key, $algorithm, 'GET', '/api/items');
}

// Get base URL
$base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hawk Authentication Test</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2 {
            color: #333;
        }
        pre {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .card {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 5px;
            cursor: pointer;
            margin-right: 10px;
        }
        button.danger {
            background-color: #f44336;
        }
        input, textarea {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .result {
            background-color: #f9f9f9;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
        }
        .status {
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            display: inline-block;
            margin-bottom: 10px;
        }
        .logged-in {
            background-color: #4CAF50;
            color: white;
        }
        .logged-out {
            background-color: #f44336;
            color: white;
        }
    </style>
</head>
<body>
    <h1>Hawk Authentication Test</h1>
    
    <div class="card">
        <h2>Register</h2>
        <form id="registerForm">
            <div>
                <label for="username">Username:</label>
                <input type="text" id="username" required>
            </div>
            <div>
                <label for="email">Email:</label>
                <input type="email" id="email" required>
            </div>
            <div>
                <label for="password">Password:</label>
                <input type="password" id="password" required>
            </div>
            <button type="submit">Register</button>
        </form>
        <div id="registerResult" class="result"></div>
    </div>
    
    <div class="card">
        <h2>Login</h2>
        <form id="loginForm">
            <div>
                <label for="loginUsername">Username:</label>
                <input type="text" id="loginUsername" required>
            </div>
            <div>
                <label for="loginPassword">Password:</label>
                <input type="password" id="loginPassword" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div id="loginResult" class="result"></div>
    </div>
    
    <div class="card">
        <h2>Hawk Credentials</h2>
        <div id="authStatus" class="status logged-out">Logged Out</div>
        <div>
            <label for="hawkId">Hawk ID:</label>
            <input type="text" id="hawkId" value="<?php echo htmlspecialchars($hawk_id); ?>">
        </div>
        <div>
            <label for="hawkKey">Hawk Key:</label>
            <input type="text" id="hawkKey" value="<?php echo htmlspecialchars($hawk_key); ?>">
        </div>
        <div>
            <label for="hawkAlgorithm">Algorithm:</label>
            <input type="text" id="hawkAlgorithm" value="<?php echo htmlspecialchars($algorithm); ?>">
        </div>
        <div style="margin-top: 10px;">
            <button id="checkAuth">Check Auth Status</button>
            <button id="logout" class="danger">Logout</button>
        </div>
        <div id="authResult" class="result"></div>
    </div>
    
    <div class="card">
        <h2>Test Hawk Authentication</h2>
        <p>Generated Authorization header:</p>
        <pre id="authHeader"><?php echo htmlspecialchars($test_header); ?></pre>
        <button id="getItems">Get Items</button>
        <div id="getItemsResult" class="result"></div>
    </div>
    
    <div class="card">
        <h2>Create Item</h2>
        <form id="createItemForm">
            <div>
                <label for="itemName">Name:</label>
                <input type="text" id="itemName" required>
            </div>
            <div>
                <label for="itemDescription">Description:</label>
                <textarea id="itemDescription" required></textarea>
            </div>
            <div>
                <label for="itemPrice">Price:</label>
                <input type="number" id="itemPrice" step="0.01" required>
            </div>
            <button type="submit">Create Item</button>
        </form>
        <div id="createItemResult" class="result"></div>
    </div>
    
    <script src="js/hawk-client.js"></script>
    <script>
        // Base URL
        const baseUrl = '<?php echo $base_url; ?>';
        
        // Register form
        document.getElementById('registerForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch(`${baseUrl}/api/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, email, password })
                });
                
                const data = await response.json();
                document.getElementById('registerResult').textContent = JSON.stringify(data, null, 2);
                
                if (data.status === 'success') {
                    document.getElementById('hawkId').value = data.data.hawk_id;
                    document.getElementById('hawkKey').value = data.data.hawk_key;
                    document.getElementById('hawkAlgorithm').value = data.data.hawk_algorithm;
                    
                    // Store in localStorage
                    localStorage.setItem('hawkId', data.data.hawk_id);
                    localStorage.setItem('hawkKey', data.data.hawk_key);
                    localStorage.setItem('hawkAlgorithm', data.data.hawk_algorithm);
                    
                    // Update auth status
                    updateAuthStatus(true);
                }
            } catch (error) {
                document.getElementById('registerResult').textContent = 'Error: ' + error.message;
            }
        });
        
        // Login form
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            try {
                const response = await fetch(`${baseUrl}/api/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                document.getElementById('loginResult').textContent = JSON.stringify(data, null, 2);
                
                if (data.status === 'success') {
                    document.getElementById('hawkId').value = data.data.hawk_id;
                    document.getElementById('hawkKey').value = data.data.hawk_key;
                    document.getElementById('hawkAlgorithm').value = data.data.hawk_algorithm;
                    
                    // Store in localStorage
                    localStorage.setItem('hawkId', data.data.hawk_id);
                    localStorage.setItem('hawkKey', data.data.hawk_key);
                    localStorage.setItem('hawkAlgorithm', data.data.hawk_algorithm);
                    
                    // Update auth status
                    updateAuthStatus(true);
                }
            } catch (error) {
                document.getElementById('loginResult').textContent = 'Error: ' + error.message;
            }
        });
        
        // Logout button
        document.getElementById('logout').addEventListener('click', async function() {
            const hawkId = document.getElementById('hawkId').value;
            const hawkKey = document.getElementById('hawkKey').value;
            const algorithm = document.getElementById('hawkAlgorithm').value;
            
            if (!hawkId || !hawkKey) {
                document.getElementById('authResult').textContent = 'Please provide Hawk credentials';
                return;
            }
            
            try {
                const response = await HawkClient.request({
                    hawkId,
                    hawkKey,
                    algorithm,
                    method: 'POST',
                    url: `${baseUrl}/api/logout`
                });
                
                const data = await response.json();
                document.getElementById('authResult').textContent = JSON.stringify(data, null, 2);
                
                if (data.status === 'success') {
                    // Clear credentials from localStorage
                    localStorage.removeItem('hawkId');
                    localStorage.removeItem('hawkKey');
                    localStorage.removeItem('hawkAlgorithm');
                    
                    // Update auth status
                    updateAuthStatus(false);
                }
            } catch (error) {
                document.getElementById('authResult').textContent = 'Error: ' + error.message;
            }
        });
        
        // Check auth status
        document.getElementById('checkAuth').addEventListener('click', async function() {
            const hawkId = document.getElementById('hawkId').value;
            const hawkKey = document.getElementById('hawkKey').value;
            const algorithm = document.getElementById('hawkAlgorithm').value;
            
            if (!hawkId || !hawkKey) {
                document.getElementById('authResult').textContent = 'Please provide Hawk credentials';
                updateAuthStatus(false);
                return;
            }
            
            try {
                // Try to get items as a test of authentication
                const response = await HawkClient.request({
                    hawkId,
                    hawkKey,
                    algorithm,
                    method: 'GET',
                    url: `${baseUrl}/api/items`
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    document.getElementById('authResult').textContent = 'Authentication valid';
                    updateAuthStatus(true);
                } else {
                    document.getElementById('authResult').textContent = 'Authentication invalid: ' + data.message;
                    updateAuthStatus(false);
                }
            } catch (error) {
                document.getElementById('authResult').textContent = 'Error: ' + error.message;
                updateAuthStatus(false);
            }
        });
        
        // Get items
        document.getElementById('getItems').addEventListener('click', async function() {
            const hawkId = document.getElementById('hawkId').value;
            const hawkKey = document.getElementById('hawkKey').value;
            const algorithm = document.getElementById('hawkAlgorithm').value;
            
            if (!hawkId || !hawkKey) {
                document.getElementById('getItemsResult').textContent = 'Please provide Hawk credentials';
                return;
            }
            
            try {
                // Generate authorization header
                const authHeader = await HawkClient.generateAuthHeader({
                    hawkId,
                    hawkKey,
                    algorithm,
                    method: 'GET',
                    url: `${baseUrl}/api/items`
                });
                
                document.getElementById('authHeader').textContent = authHeader;
                
                // Make request
                const response = await fetch(`${baseUrl}/api/items`, {
                    headers: {
                        'Authorization': authHeader
                    }
                });
                
                const data = await response.json();
                document.getElementById('getItemsResult').textContent = JSON.stringify(data, null, 2);
                
                // Update auth status based on response
                updateAuthStatus(response.ok);
            } catch (error) {
                document.getElementById('getItemsResult').textContent = 'Error: ' + error.message;
                updateAuthStatus(false);
            }
        });
        
        // Create item
        document.getElementById('createItemForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const name = document.getElementById('itemName').value;
            const description = document.getElementById('itemDescription').value;
            const price = document.getElementById('itemPrice').value;
            
            const hawkId = document.getElementById('hawkId').value;
            const hawkKey = document.getElementById('hawkKey').value;
            const algorithm = document.getElementById('hawkAlgorithm').value;
            
            if (!hawkId || !hawkKey) {
                document.getElementById('createItemResult').textContent = 'Please provide Hawk credentials';
                return;
            }
            
            try {
                const response = await HawkClient.request({
                    hawkId,
                    hawkKey,
                    algorithm,
                    method: 'POST',
                    url: `${baseUrl}/api/items`,
                    body: { name, description, price }
                });
                
                const data = await response.json();
                document.getElementById('createItemResult').textContent = JSON.stringify(data, null, 2);
                
                // Update auth status based on response
                updateAuthStatus(response.ok);
            } catch (error) {
                document.getElementById('createItemResult').textContent = 'Error: ' + error.message;
                updateAuthStatus(false);
            }
        });
        
        // Update authentication status UI
        function updateAuthStatus(isLoggedIn) {
            const authStatus = document.getElementById('authStatus');
            
            if (isLoggedIn) {
                authStatus.textContent = 'Logged In';
                authStatus.className = 'status logged-in';
            } else {
                authStatus.textContent = 'Logged Out';
                authStatus.className = 'status logged-out';
            }
        }
        
        // Load saved credentials from localStorage and check auth status
        window.addEventListener('DOMContentLoaded', function() {
            const hawkId = localStorage.getItem('hawkId');
            const hawkKey = localStorage.getItem('hawkKey');
            const algorithm = localStorage.getItem('hawkAlgorithm');
            
            if (hawkId) document.getElementById('hawkId').value = hawkId;
            if (hawkKey) document.getElementById('hawkKey').value = hawkKey;
            if (algorithm) document.getElementById('hawkAlgorithm').value = algorithm;
            
            // Automatically check auth status on page load
            if (hawkId && hawkKey) {
                document.getElementById('checkAuth').click();
            }
        });
    </script>
</body>
</html> 