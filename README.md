# RESTful PHP API with Hawk Authentication

A secure RESTful API built with PHP, MySQL, and custom Hawk Authentication implementation with token revocation.

## Setup Instructions

1. **Database Setup**:
   - Import the `database.sql` file into your MySQL database using phpMyAdmin or run the SQL commands directly.
   - The SQL file will create the database and required tables.

2. **Configuration**:
   - Update the database connection details in `config/database.php` if needed.

3. **Web Server**:
   - Make sure your web server (Apache) is running.
   - Place all files in your web server directory (e.g., htdocs for XAMPP).

4. **Testing**:
   - Open `test-hawk.php` in your browser to test the Hawk authentication.

## API Endpoints

### Authentication

#### Register User
- **URL**: `/api/register`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "username": "your_username",
    "email": "your_email@example.com",
    "password": "your_password"
  }
  ```
- **Response**: Returns user ID, username, and Hawk credentials (hawk_id, hawk_key, hawk_algorithm).

#### Login
- **URL**: `/api/login`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```
- **Response**: Returns user ID, username, and Hawk credentials (hawk_id, hawk_key, hawk_algorithm).

#### Logout
- **URL**: `/api/logout`
- **Method**: `POST`
- **Authentication**: Hawk Authentication
- **Note**: Revokes the Hawk ID by adding it to a blacklist in the database.

### Items CRUD Operations

#### Create Item
- **URL**: `/api/items`
- **Method**: `POST`
- **Authentication**: Hawk Authentication
- **Body**:
  ```json
  {
    "name": "Item Name",
    "description": "Item Description",
    "price": 99.99
  }
  ```

#### Get All Items
- **URL**: `/api/items`
- **Method**: `GET`

#### Get Single Item
- **URL**: `/api/items/{id}`
- **Method**: `GET`

#### Update Item
- **URL**: `/api/items/{id}`
- **Method**: `PUT`
- **Authentication**: Hawk Authentication
- **Body**:
  ```json
  {
    "name": "Updated Name",
    "description": "Updated Description",
    "price": 199.99
  }
  ```

#### Delete Item
- **URL**: `/api/items/{id}`
- **Method**: `DELETE`
- **Authentication**: Hawk Authentication

#### Search Items
- **URL**: `/api/items/search?q=search_term`
- **Method**: `GET`

## Hawk Authentication

Hawk is a HTTP authentication scheme that provides a method for making authenticated HTTP requests with partial cryptographic verification of the request.

### How to Use Hawk Authentication

1. **Get Hawk Credentials**: Register or login to get your Hawk ID and Key.

2. **Generate Hawk Authorization Header**:
   - Create a nonce (a random string that is unique for each request)
   - Get the current timestamp in seconds
   - Create a normalized string with request details
   - Calculate the MAC (Message Authentication Code) using your Hawk key
   - Format the Authorization header

3. **Example Authorization Header**:
   ```
   Authorization: Hawk id="your_hawk_id", ts="1353832234", nonce="j4h3g2", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="
   ```

### Token Revocation System

The API includes a token revocation system to properly handle logout:

1. When a user logs out, their Hawk ID is added to a `revoked_tokens` table in the database.
2. All authenticated requests check if the Hawk ID has been revoked before proceeding.
3. Once a token is revoked, it can no longer be used for authentication.
4. To use the API again after logout, the user must log in to obtain new Hawk credentials.

### Using Hawk with Postman

1. In Postman, select "Hawk Authentication" from the Authorization tab.
2. Enter your Hawk ID and Hawk Key.
3. Select the algorithm (default: SHA256).
4. Postman will automatically generate the correct Authorization header for each request.

### Using Hawk with JavaScript

We've included a JavaScript client for Hawk authentication in `js/hawk-client.js`. Here's how to use it:

```javascript
// After login/registration to get hawk credentials
const hawkId = 'hawk_1234567890abcdef';
const hawkKey = '1234567890abcdef1234567890abcdef';
const algorithm = 'sha256';

// Make authenticated request
async function createItem() {
    const response = await HawkClient.request({
        hawkId: hawkId,
        hawkKey: hawkKey,
        algorithm: algorithm,
        method: 'POST',
        url: 'http://localhost/api/items',
        body: {
            name: 'Test Item',
            description: 'This is a test item',
            price: 99.99
        }
    });
    
    const data = await response.json();
    console.log(data);
}
```

## Security Notes

- All write operations (POST, PUT, DELETE) require Hawk authentication.
- Passwords are securely hashed before storage.
- Hawk credentials are generated using cryptographically secure methods.
- Revoked tokens are tracked in the database to prevent use after logout.

## Error Handling

All endpoints return appropriate HTTP status codes and JSON responses with the following structure:

```json
{
  "status": "success|error",
  "message": "Description of the result",
  "data": { ... } // Optional data object
}
``` 