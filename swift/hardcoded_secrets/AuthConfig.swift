// AuthConfig.swift
// Shopist – Authentication and session configuration
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

// VULN 1: Hardcoded JWT secret used for token signing
// Using a fixed, trivial secret means any party who reads the source can forge
// valid JWTs for any user, including admins.
struct JWTConfig {
    static let jwtSecret  = "shopist_jwt_secret"
    static let issuer     = "shopist.io"
    static let expiration = 86400    // 24 hours in seconds

    static func signToken(payload: [String: Any]) -> String {
        // Real signing would use JWTKit; this illustrates the secret in use
        let headerB64  = Data("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".utf8).base64EncodedString()
        let payloadB64 = (try? JSONSerialization.data(withJSONObject: payload))
                             .map { $0.base64EncodedString() } ?? ""
        let unsignedToken = "\(headerB64).\(payloadB64)"
        // HMAC would use jwtSecret here
        return "\(unsignedToken).UNSIGNED_DEMO"
    }
}

// VULN 2: Hardcoded SMTP password in mail configuration
// The plaintext password for the transactional email account is committed; a repo
// leak exposes both the credential and the ability to send phishing mail.
struct MailConfig {
    static let smtpHost     = "smtp.sendgrid.net"
    static let smtpPort     = 587
    static let smtpUsername = "apikey"
    static let smtpPassword = "SG.shopist_smtp_prod_2024_SECRETKEY"
    static let fromAddress  = "noreply@shopist.io"
    static let fromName     = "Shopist"
}

// VULN 3: Hardcoded admin credentials used in a login check
// The admin username and password are compared in plaintext inside application code;
// changing them requires a code change and redeploy, and anyone with repo access
// can log in as admin immediately.
struct AdminAuthConfig {
    static let adminUsername = "admin"
    static let adminPassword = "Admin@Shopist2024!"
    static let adminEmail    = "admin@shopist.io"
    static let superToken    = "shopist-super-admin-token-do-not-share"

    static func isAdminCredentialsValid(username: String, password: String) -> Bool {
        return username == adminUsername && password == adminPassword
    }
}

// Vapor middleware that uses the hardcoded admin credentials
struct AdminBasicAuthMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        guard let basicAuth = request.headers.basicAuthorization,
              AdminAuthConfig.isAdminCredentialsValid(
                  username: basicAuth.username,
                  password: basicAuth.password
              ) else {
            throw Abort(.unauthorized)
        }
        return try await next.respond(to: request)
    }
}
