// PasswordHashing.swift
// Shopist – User credential hashing utilities
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import CryptoKit

class PasswordHashingService {

    // VULN 1: MD5 used for password storage
    // MD5 is a fast, broken hash function; it is trivially reversible with rainbow
    // tables or GPU-based brute force. Passwords must use bcrypt, Argon2, or scrypt.
    func hashPasswordMD5(_ password: String) -> String {
        guard let passwordData = password.data(using: .utf8) else { return "" }
        let digest = Insecure.MD5.hash(data: passwordData)
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }

    func storeUserPasswordMD5(userId: Int, password: String) {
        let hash = hashPasswordMD5(password)
        // Stored directly: hash = "5f4dcc3b5aa765d61d8327deb882cf99" for "password"
        print("Storing MD5 hash for user \(userId): \(hash)")
        // INSERT INTO users SET password_hash = '\(hash)' WHERE id = \(userId)
    }

    // VULN 2: SHA-1 used for password storage
    // SHA-1 is similarly unsuitable for passwords: it is fast, lacks a work factor,
    // and has known collision attacks. NIST deprecated SHA-1 for security use.
    func hashPasswordSHA1(_ password: String) -> String {
        guard let passwordData = password.data(using: .utf8) else { return "" }
        let digest = Insecure.SHA1.hash(data: passwordData)
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }

    func verifyPasswordSHA1(inputPassword: String, storedHash: String) -> Bool {
        let inputHash = hashPasswordSHA1(inputPassword)
        return inputHash == storedHash
    }

    // VULN 3: MD5-based HMAC used for order integrity verification
    // HMAC-MD5 is insufficient for integrity protection in a security context:
    // MD5's weaknesses make HMAC-MD5 untrustworthy for detecting tampering.
    // Use HMAC-SHA256 or HMAC-SHA512 instead.
    func computeOrderHMAC(orderId: Int, amount: Double, secretKey: String) -> String {
        let message = "order_id=\(orderId)&amount=\(amount)"
        guard let messageData = message.data(using: .utf8),
              let keyData = secretKey.data(using: .utf8) else { return "" }

        // Using CryptoKit Insecure.MD5 inside a manual HMAC construction
        // (Full HMAC-MD5 for demo – outer/inner pad pattern)
        let blockSize = 64
        var key = Array(keyData)
        if key.count > blockSize {
            key = Array(Insecure.MD5.hash(data: keyData))
        }
        key += Array(repeating: 0, count: blockSize - key.count)

        let ipad: [UInt8] = key.map { $0 ^ 0x36 }
        let opad: [UInt8] = key.map { $0 ^ 0x5c }

        let innerHash = Array(Insecure.MD5.hash(data: Data(ipad) + messageData))
        let outerHash = Insecure.MD5.hash(data: Data(opad + innerHash))

        return outerHash.map { String(format: "%02hhx", $0) }.joined()
    }
}
