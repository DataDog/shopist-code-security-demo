// Shopist Shopping Cart - Code Security Demo
// Contains LOW, MEDIUM, and HIGH severity violations

const { exec, execSync } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const mysql = require('mysql');

// ============================================================
// HIGH SEVERITY VIOLATIONS
// ============================================================

// HIGH: Hardcoded credentials
const DB_PASSWORD = "ProductionPassword123!";
const STRIPE_SECRET_KEY = "sk_live_1234567890abcdef";
const JWT_SECRET = "super-secret-jwt-key";

// HIGH: SQL Injection vulnerability
function getUserById(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return db.query(query);
}

// HIGH: SQL Injection in search
function searchProducts(searchTerm) {
    const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
    return db.query(query);
}

// HIGH: Command Injection
function generateInvoice(orderId) {
    exec('wkhtmltopdf /tmp/order_' + orderId + '.html /tmp/invoice_' + orderId + '.pdf');
}

// HIGH: Command Injection with user input
function processUpload(filename) {
    execSync('convert /tmp/' + filename + ' /var/www/images/' + filename);
}

// HIGH: Prototype pollution vulnerability
function mergeConfig(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

// HIGH: Path traversal
function getProductImage(imageName) {
    const imagePath = '/var/www/images/' + imageName;
    return fs.readFileSync(imagePath);
}

// HIGH: Arbitrary file write
function saveUserAvatar(userId, filename, data) {
    fs.writeFileSync('/var/www/avatars/' + filename, data);
}

// HIGH: Unsafe deserialization
function loadSession(sessionData) {
    return eval('(' + sessionData + ')');
}

// HIGH: XSS vulnerability (DOM-based)
function displayUserInput(input) {
    document.getElementById('output').innerHTML = input;
}

// HIGH: XSS in template
function renderComment(comment) {
    return '<div class="comment">' + comment.text + '</div>';
}

// ============================================================
// MEDIUM SEVERITY VIOLATIONS
// ============================================================

// MEDIUM: Weak cryptographic algorithm (MD5)
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// MEDIUM: Weak hashing (SHA1)
function generateToken(data) {
    return crypto.createHash('sha1').update(data).digest('hex');
}

// MEDIUM: Insecure random number generation
function generateSessionId() {
    return Math.random().toString(36).substring(2);
}

// MEDIUM: Insecure random for tokens
function generateResetToken() {
    return Math.floor(Math.random() * 1000000).toString();
}

// MEDIUM: Missing input validation
function updateProfile(userId, profileData) {
    db.query('UPDATE users SET profile = ? WHERE id = ?', [profileData, userId]);
}

// MEDIUM: Information disclosure
function handleError(error) {
    return {
        message: error.message,
        stack: error.stack,
        query: error.sql
    };
}

// MEDIUM: Insecure cookie settings
function setSessionCookie(res, sessionId) {
    res.cookie('session', sessionId, {
        secure: false,
        httpOnly: false,
        sameSite: 'none'
    });
}

// MEDIUM: Debug information exposed
const DEBUG = true;
function logDebug(message, data) {
    if (DEBUG) {
        console.log('DEBUG:', message, JSON.stringify(data));
    }
}

// ============================================================
// LOW SEVERITY VIOLATIONS
// ============================================================

// LOW: Using var instead of let/const
var items = [];
var total = 0;
var discount = 0;

// LOW: console.log in production
function addItem(item) {
    items.push(item);
    console.log("Added item: " + item.name);
}

// LOW: Loose equality
function removeItem(id) {
    for (var i = 0; i < items.length; i++) {
        if (items[i].id == id) {
            items.splice(i, 1);
            break;
        }
    }
}

// LOW: Inefficient loop
function calculateTotal() {
    var sum = 0;
    for (var i = 0; i < items.length; i++) {
        sum = sum + items[i].price;
    }
    total = sum;
    return sum;
}

// LOW: Multiple loose equality comparisons
function applyDiscount(code) {
    if (code == "SAVE10") {
        discount = 10;
    } else if (code == "SAVE20") {
        discount = 20;
    } else if (code == "SAVE50") {
        discount = 50;
    }
    console.log("Discount applied: " + discount);
}

// LOW: Empty catch block
function checkout(user, payment) {
    var valid = true;
    if (user == null) {
        valid = false;
    }
    if (payment == undefined) {
        valid = false;
    }
    if (items.length == 0) {
        valid = false;
    }
    
    if (valid == true) {
        try {
            processPayment(payment);
        } catch (e) {
            // ignore error
        }
    }
    
    return valid;
}

// LOW: Code duplication
function formatPrice(price) {
    return "$" + price.toString();
}

function formatAmount(amount) {
    return "$" + amount.toString();
}

function formatMoney(value) {
    return "$" + value.toString();
}

// LOW: Boolean comparison anti-pattern
function isValidUser(user) {
    if (user.active == true) {
        return true;
    } else {
        return false;
    }
}

// LOW: Unused variables
function processOrder(order) {
    var timestamp = Date.now();
    var unused = "never used";
    var temp = null;
    
    return order.total;
}

// LOW: Magic numbers
function calculateShipping(weight) {
    if (weight < 1) {
        return 5.99;
    } else if (weight < 5) {
        return 9.99;
    } else if (weight < 10) {
        return 14.99;
    } else {
        return 24.99;
    }
}

function debugCart() {
    console.log(items);
    console.log(total);
    console.log(discount);
}

module.exports = {
    addItem,
    removeItem,
    calculateTotal,
    checkout
};

