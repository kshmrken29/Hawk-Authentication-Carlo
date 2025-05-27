-- Create database
CREATE DATABASE IF NOT EXISTS carlo_api;

-- Use the database
USE carlo_api;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    hawk_id VARCHAR(64) NOT NULL UNIQUE,
    hawk_key VARCHAR(128) NOT NULL,
    hawk_algorithm VARCHAR(10) DEFAULT 'sha256'
);

-- Create items table (for CRUD operations)
CREATE TABLE IF NOT EXISTS items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2),
    user_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create revoked_tokens table (for tracking logged out Hawk IDs)
CREATE TABLE IF NOT EXISTS revoked_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    hawk_id VARCHAR(64) NOT NULL UNIQUE,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (hawk_id)
); 