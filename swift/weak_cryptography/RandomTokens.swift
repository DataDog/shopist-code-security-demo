// RandomTokens.swift
// Shopist – Token and nonce generation utilities
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import GameplayKit

class TokenGenerationService {

    // VULN 1: arc4random() is not a cryptographically secure PRNG for secret tokens
    // arc4random is seeded automatically but its output is NOT suitable for
    // security-sensitive tokens (password-reset links, CSRF nonces). On some
    // platforms its internal state can be predicted; even where it can't, the
    // 32-bit output space is far too small. Use SecRandomCopyBytes or
    // CryptoKit's SymmetricKey for security tokens.
    func generatePasswordResetToken() -> String {
        var token = ""
        for _ in 0..<32 {
            let char = arc4random() % 36
            if char < 10 {
                token += String(char)
            } else {
                token += String(UnicodeScalar(UInt32("a") + char - 10)!)
            }
        }
        return token
    }

    // VULN 2: drand48() produces a predictable, seeded linear-congruential sequence
    // drand48 / srand48 are classic C library PRNGs. Their output is entirely
    // deterministic from the seed and the sequence is easily reversed. Using
    // time-based seeding (as here) makes the seed guessable within a small window.
    func generateOrderNonce() -> String {
        srand48(Int(Date().timeIntervalSince1970))   // time-based seed – easily guessed
        var nonce = ""
        for _ in 0..<16 {
            let byte = Int(drand48() * 256)
            nonce += String(format: "%02x", byte)
        }
        return nonce
    }

    // VULN 3: GKRandomSource (GameplayKit) is not cryptographically secure
    // GKMersenneTwisterRandomSource and GKLinearCongruentialRandomSource are
    // designed for game simulations, not cryptography. Their internal state can be
    // reconstructed from a short sequence of outputs. GKARC4RandomSource is slightly
    // better but still not a cryptographic PRNG.
    func generateCartSessionToken() -> String {
        let random = GKMersenneTwisterRandomSource()
        var token = ""
        for _ in 0..<8 {
            let value = random.nextInt(upperBound: Int(UInt32.max))
            token += String(format: "%08x", value)
        }
        return token
    }

    // generateCSRFToken uses the same weak approach – drand48 with time seed
    func generateCSRFToken(for userId: Int) -> String {
        srand48(userId ^ Int(Date().timeIntervalSince1970))
        let part1 = Int(drand48() * Double(UInt32.max))
        let part2 = Int(drand48() * Double(UInt32.max))
        return String(format: "%08x%08x", part1, part2)
    }
}
