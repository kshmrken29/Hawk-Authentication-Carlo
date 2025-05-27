<?php
/**
 * Simple Hawk Authentication Implementation
 * Based on the Hawk specification: https://github.com/hueniverse/hawk
 */

class HawkAuth {
    // Supported hash algorithms
    private static $algorithms = [
        'sha1' => true,
        'sha256' => true
    ];
    
    /**
     * Generate a Hawk ID
     * 
     * @return string
     */
    public static function generateId() {
        return 'hawk_' . bin2hex(random_bytes(8));
    }
    
    /**
     * Generate a Hawk Key
     * 
     * @param int $length Length of the key
     * @return string
     */
    public static function generateKey($length = 32) {
        return bin2hex(random_bytes($length));
    }
    
    /**
     * Parse Hawk Authorization header
     * 
     * @param string $header Authorization header
     * @return array|false Parsed attributes or false on failure
     */
    public static function parseHeader($header) {
        if (empty($header) || strpos($header, 'Hawk ') !== 0) {
            return false;
        }
        
        $attributes = [];
        $headerParts = explode(',', substr($header, 5));
        
        foreach ($headerParts as $part) {
            $part = trim($part);
            if (preg_match('/^([a-zA-Z]+)="([^"]*)"$/', $part, $matches)) {
                $attributes[$matches[1]] = $matches[2];
            }
        }
        
        // Validate required attributes
        $required = ['id', 'ts', 'nonce', 'mac'];
        foreach ($required as $field) {
            if (!isset($attributes[$field])) {
                return false;
            }
        }
        
        return $attributes;
    }
    
    /**
     * Calculate MAC for request
     * 
     * @param array $credentials User credentials (key, algorithm)
     * @param array $options Request options (method, uri, host, port, ts, nonce, hash, ext)
     * @return string MAC
     */
    public static function calculateMac($credentials, $options) {
        if (!isset(self::$algorithms[$credentials['algorithm']])) {
            throw new Exception('Unsupported algorithm: ' . $credentials['algorithm']);
        }
        
        // Create normalized string
        $normalized = "hawk.1.header\n" .
            $options['ts'] . "\n" .
            $options['nonce'] . "\n" .
            strtoupper($options['method']) . "\n" .
            $options['uri'] . "\n" .
            $options['host'] . "\n" .
            $options['port'] . "\n" .
            (isset($options['hash']) ? $options['hash'] : '') . "\n" .
            (isset($options['ext']) ? $options['ext'] : '') . "\n";
        
        // Calculate MAC
        return base64_encode(hash_hmac($credentials['algorithm'], $normalized, $credentials['key'], true));
    }
    
    /**
     * Verify request
     * 
     * @param array $credentials User credentials (key, algorithm)
     * @param array $attributes Parsed header attributes
     * @param string $method HTTP method
     * @param string $uri Request URI
     * @param string $host Host
     * @param int $port Port
     * @return bool True if valid
     */
    public static function verify($credentials, $attributes, $method, $uri, $host, $port) {
        $options = [
            'ts' => $attributes['ts'],
            'nonce' => $attributes['nonce'],
            'method' => $method,
            'uri' => $uri,
            'host' => $host,
            'port' => $port,
            'hash' => isset($attributes['hash']) ? $attributes['hash'] : '',
            'ext' => isset($attributes['ext']) ? $attributes['ext'] : ''
        ];
        
        $calculatedMac = self::calculateMac($credentials, $options);
        
        return hash_equals($calculatedMac, $attributes['mac']);
    }
    
    /**
     * Generate client header for testing
     * 
     * @param string $id Hawk ID
     * @param string $key Hawk Key
     * @param string $algorithm Hash algorithm
     * @param string $method HTTP method
     * @param string $uri Request URI
     * @param string $host Host
     * @param int $port Port
     * @return string Authorization header
     */
    public static function generateClientHeader($id, $key, $algorithm, $method, $uri, $host, $port) {
        $ts = time();
        $nonce = bin2hex(random_bytes(4));
        
        $credentials = [
            'key' => $key,
            'algorithm' => $algorithm
        ];
        
        $options = [
            'ts' => $ts,
            'nonce' => $nonce,
            'method' => $method,
            'uri' => $uri,
            'host' => $host,
            'port' => $port,
            'hash' => '',
            'ext' => ''
        ];
        
        $mac = self::calculateMac($credentials, $options);
        
        return 'Hawk id="' . $id . '", ts="' . $ts . '", nonce="' . $nonce . '", mac="' . $mac . '"';
    }
}
?> 