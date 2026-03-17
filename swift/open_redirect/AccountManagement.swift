// AccountManagement.swift
// Shopist – Account management redirect handling
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct AccountManagementController: RouteCollection {

    func boot(routes: RoutesBuilder) throws {
        let account = routes.grouped("account")
        account.post("password-reset", "confirm", use: passwordResetConfirm)
        account.get("profile", use: profileRedirect)
        account.post("social", "link", use: linkSocialAccount)
    }

    // VULN 1: Open Redirect via unvalidated `redirectTo` parameter in password reset
    // After the user confirms their new password, the application redirects them to
    // `redirectTo`. An attacker who controls the password-reset link (e.g., via
    // phishing) can set redirectTo to a credential-harvesting page.
    func passwordResetConfirm(req: Request) async throws -> Response {
        struct ResetBody: Content {
            var token: String
            var newPassword: String
            var redirectTo: String   // e.g., "/account/login"
        }
        let body = try req.content.decode(ResetBody.self)

        // Validate token and update password (omitted)
        req.logger.info("Password reset confirmed for token \(body.token)")

        // Attacker input: "https://evil.example.com/password-was-stolen"
        return req.redirect(to: body.redirectTo)
    }

    // VULN 2: Open Redirect using the Referer header directly as redirect destination
    // The profile page redirects unauthenticated users back to where they came from
    // using the raw Referer header. An attacker can craft a link that sets Referer
    // to an external URL, then send the victim a link to /account/profile.
    func profileRedirect(req: Request) throws -> Response {
        // Check auth (simulate unauthenticated)
        let isAuthenticated = false
        guard isAuthenticated else {
            // Use Referer header as "return to" URL without any origin validation
            let referer = req.headers.first(name: .referer) ?? "/login"
            // Attacker controls Referer header:
            // curl -H "Referer: https://evil.example.com" https://shopist.io/account/profile
            return req.redirect(to: referer)
        }
        return Response(status: .ok, body: .init(string: "Profile page"))
    }

    // VULN 3: Open Redirect via unvalidated `callbackUrl` in social account linking
    // When linking a social account (Google, Facebook), the app stores a `callbackUrl`
    // to redirect to after the OAuth flow completes. The callback URL is not validated
    // against an allowlist, enabling open redirect post-linking.
    func linkSocialAccount(req: Request) async throws -> Response {
        struct LinkRequest: Content {
            var provider: String      // e.g., "google"
            var callbackUrl: String   // e.g., "/account/settings?linked=google"
        }
        let body = try req.content.decode(LinkRequest.self)

        // Initiate OAuth with provider (omitted)
        req.logger.info("Linking \(body.provider) account")

        // After provider redirects back, the app blindly follows callbackUrl:
        // Attacker input: "https://phishing.example.com/session-stolen"
        return req.redirect(to: body.callbackUrl)
    }
}
