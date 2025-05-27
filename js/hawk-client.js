/**
 * Simple Hawk Authentication Client for JavaScript
 * For demonstration purposes only
 */

class HawkClient {
    /**
     * Generate a random string for nonce
     * 
     * @param {number} length Length of the nonce
     * @returns {string} Random string
     */
    static generateNonce(length = 8) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    /**
     * Calculate HMAC
     * 
     * @param {string} algorithm Hash algorithm (sha1, sha256)
     * @param {string} key Secret key
     * @param {string} message Message to hash
     * @returns {string} Base64 encoded HMAC
     */
    static async calculateHmac(algorithm, key, message) {
        // Convert algorithm name to Web Crypto format
        const algoMap = {
            'sha1': 'SHA-1',
            'sha256': 'SHA-256'
        };
        
        const encoder = new TextEncoder();
        const keyData = encoder.encode(key);
        const messageData = encoder.encode(message);
        
        // Import key
        const cryptoKey = await crypto.subtle.importKey(
            'raw', 
            keyData, 
            { name: 'HMAC', hash: { name: algoMap[algorithm] } },
            false, 
            ['sign']
        );
        
        // Sign message
        const signature = await crypto.subtle.sign(
            'HMAC',
            cryptoKey,
            messageData
        );
        
        // Convert to base64
        return btoa(String.fromCharCode(...new Uint8Array(signature)));
    }

    /**
     * Generate Hawk authorization header
     * 
     * @param {Object} options Options
     * @param {string} options.hawkId Hawk ID
     * @param {string} options.hawkKey Hawk Key
     * @param {string} options.algorithm Hash algorithm (sha1, sha256)
     * @param {string} options.method HTTP method
     * @param {string} options.url Request URL
     * @returns {Promise<string>} Authorization header
     */
    static async generateAuthHeader(options) {
        const { hawkId, hawkKey, algorithm, method, url } = options;
        
        // Parse URL
        const urlObj = new URL(url);
        const host = urlObj.hostname;
        const port = urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80);
        const uri = urlObj.pathname + urlObj.search;
        
        // Generate timestamp and nonce
        const ts = Math.floor(Date.now() / 1000);
        const nonce = this.generateNonce();
        
        // Create normalized string
        const normalized = [
            'hawk.1.header',
            ts,
            nonce,
            method.toUpperCase(),
            uri,
            host,
            port,
            '',  // hash
            ''   // ext
        ].join('\n');
        
        // Calculate MAC
        const mac = await this.calculateHmac(algorithm, hawkKey, normalized);
        
        // Return header
        return `Hawk id="${hawkId}", ts="${ts}", nonce="${nonce}", mac="${mac}"`;
    }

    /**
     * Make authenticated request
     * 
     * @param {Object} options Options
     * @param {string} options.hawkId Hawk ID
     * @param {string} options.hawkKey Hawk Key
     * @param {string} options.algorithm Hash algorithm (sha1, sha256)
     * @param {string} options.method HTTP method
     * @param {string} options.url Request URL
     * @param {Object} options.body Request body (optional)
     * @returns {Promise<Response>} Fetch response
     */
    static async request(options) {
        const { method, url, body } = options;
        
        // Generate authorization header
        const authHeader = await this.generateAuthHeader(options);
        
        // Prepare fetch options
        const fetchOptions = {
            method,
            headers: {
                'Authorization': authHeader,
                'Content-Type': 'application/json'
            }
        };
        
        // Add body if provided
        if (body) {
            fetchOptions.body = JSON.stringify(body);
        }
        
        // Make request
        return fetch(url, fetchOptions);
    }
}

// Example usage:
/*
// After login/registration to get hawk credentials
const hawkId = 'hawk_1234567890abcdef';
const hawkKey = '1234567890abcdef1234567890abcdef';
const algorithm = 'sha256';

// Store credentials in localStorage or sessionStorage
localStorage.setItem('hawkId', hawkId);
localStorage.setItem('hawkKey', hawkKey);
localStorage.setItem('hawkAlgorithm', algorithm);

// Make authenticated request
async function createItem() {
    const response = await HawkClient.request({
        hawkId: localStorage.getItem('hawkId'),
        hawkKey: localStorage.getItem('hawkKey'),
        algorithm: localStorage.getItem('hawkAlgorithm'),
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

createItem();
*/ 