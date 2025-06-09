<?php
// Redirect to README.md or display API info
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RESTful PHP API with Hawk Authentication</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #333;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        h2 {
            color: #444;
            margin-top: 30px;
        }
        h3 {
            color: #555;
            margin-top: 20px;
        }
        code {
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
        }
        pre {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .endpoint {
            background-color: #f9f9f9;
            border-left: 4px solid #4CAF50;
            padding: 10px 15px;
            margin-bottom: 20px;
        }
        .method {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            margin-right: 10px;
        }
        .get { background-color: #61affe; }
        .post { background-color: #49cc90; }
        .put { background-color: #fca130; }
        .delete { background-color: #f93e3e; }
    </style>
</head>
<body>
    <h1>RESTful PHP API with Hawk Authentication</h1>
    
    <p>Welcome to the RESTful PHP API. This API provides authentication and CRUD operations for items with secure Hawk authentication.</p>
    
    <h2>Setup</h2>
    <ol>
        <li>Run <code>composer install</code> to install dependencies</li>
        <li>Import <code>database.sql</code> into your MySQL database</li>
        <li>Update database connection details in <code>config/database.php</code> if needed</li>
        <li>Ensure your web server is running</li>
    </ol>
    
    <h2>Authentication Endpoints</h2>
    
    <div class="endpoint">
        <h3><span class="method post">POST</span> /api/register</h3>
        <p>Register a new user and get Hawk credentials.</p>
        <p><strong>Body:</strong></p>
        <pre>{
  "username": "your_username",
  "email": "your_email@example.com",
  "password": "your_password"
}</pre>
    </div>
    
    <div class="endpoint">
        <h3><span class="method post">POST</span> /api/login</h3>
        <p>Login and get Hawk credentials.</p>
        <p><strong>Body:</strong></p>
        <pre>{
  "username": "your_username",
  "password": "your_password"
}</pre>
    </div>
    
    <div class="endpoint">
        <h3><span class="method post">POST</span> /api/logout</h3>
        <p>Logout (requires Hawk Authentication).</p>
    </div>
    
    <h2>Items Endpoints</h2>
    
    <div class="endpoint">
        <h3><span class="method get">GET</span> /api/items</h3>
        <p>Get all items.</p>
    </div>
    
    <div class="endpoint">
        <h3><span class="method get">GET</span> /api/items/{id}</h3>
        <p>Get a single item by ID.</p>
    </div>
    
    <div class="endpoint">
        <h3><span class="method post">POST</span> /api/items</h3>
        <p>Create a new item (requires Hawk Authentication).</p>
        <p><strong>Body:</strong></p>
        <pre>{
  "name": "Item Name",
  "description": "Item Description",
  "price": 99.99
}</pre>
    </div>
    
    <div class="endpoint">
        <h3><span class="method put">PUT</span> /api/items/{id}</h3>
        <p>Update an existing item (requires Hawk Authentication).</p>
        <p><strong>Body:</strong></p>
        <pre>{
  "name": "Updated Name",
  "description": "Updated Description",
  "price": 199.99
}</pre>
    </div>
    
    <div class="endpoint">
        <h3><span class="method delete">DELETE</span> /api/items/{id}</h3>
        <p>Delete an item (requires Hawk Authentication).</p>
    </div>
    
    <div class="endpoint">
        <h3><span class="method get">GET</span> /api/items/search?q=search_term</h3>
        <p>Search for items by name or description.</p>
    </div>
    
    <h2>Hawk Authentication</h2>
    <p>This API uses Hawk Authentication for secure requests. After registering or logging in, you'll receive Hawk credentials:</p>
    <ul>
        <li><strong>hawk_id</strong>: Your unique identifier</li>
        <li><strong>hawk_key</strong>: Your secret key used for signing requests</li>
        <li><strong>hawk_algorithm</strong>: The algorithm used for signing (default: sha256)</li>
    </ul>
    
    <h3>Using Hawk with Postman</h3>
    <ol>
        <li>In Postman, select "Hawk Authentication" from the Authorization tab</li>
        <li>Enter your Hawk ID and Hawk Key</li>
        <li>Select the algorithm (default: SHA256)</li>
        <li>Postman will automatically generate the correct Authorization header for each request</li>
    </ol>
    
    <h2>Security Notes</h2>
    <ul>
        <li>All write operations require Hawk authentication</li>
        <li>Passwords are securely hashed</li>
        <li>Hawk credentials are generated using cryptographically secure methods</li>
    </ul>
    
    <h2>For More Information</h2>
    <p>See the <a href="README.md">README.md</a> file for more detailed documentation.</p>
</body>
</html> 