<?php
// Database configuration
class Database {
    private $host = 'localhost';
    private $username = 'root';
    private $password = '';
    private $database = 'carlo_api';
    public $conn;

    // Get database connection
    public function getConnection() {
        $this->conn = null;
        
        try {
            $this->conn = new mysqli($this->host, $this->username, $this->password, $this->database);
            
            if ($this->conn->connect_error) {
                throw new Exception("Connection failed: " . $this->conn->connect_error);
            }
        } catch(Exception $e) {
            echo "Database connection error: " . $e->getMessage();
        }
        
        return $this->conn;
    }
}
?> 