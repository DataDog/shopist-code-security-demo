// CheckoutFlow.swift
// Shopist – Checkout flow redirect handling
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct CheckoutFlowController: RouteCollection {

    func boot(routes: RoutesBuilder) throws {
        routes.get("login", use: loginRedirect)
        routes.post("checkout", "complete", use: checkoutComplete)
        routes.get("oauth", "callback", use: oauthCallback)
    }

    // VULN 1: Open Redirect via unvalidated `next` parameter after login
    // Vapor's `req.redirect(to:)` issues an HTTP 303 to whatever URL is supplied
    // in the `next` query parameter. No origin check is performed, so an attacker
    // can craft a login link that redirects the victim to a phishing site after
    // successful authentication.
    // Example exploit URL: /login?next=https://evil.example.com/fake-shopist
    func loginRedirect(req: Request) throws -> Response {
        guard let next = req.query[String.self, at: "next"] else {
            return req.redirect(to: "/dashboard")
        }

        // Simulate authentication check passed (session already valid)
        // No validation that `next` is a relative URL or belongs to shopist.io
        return req.redirect(to: next)
    }

    // VULN 2: Open Redirect via unvalidated `returnUrl` parameter after checkout
    // After a successful payment, the application redirects the user to `returnUrl`
    // to show a confirmation page. Merchants can embed malicious return URLs in
    // checkout sessions.
    func checkoutComplete(req: Request) async throws -> Response {
        struct CheckoutBody: Content {
            var orderId: Int
            var returnUrl: String   // e.g., "/orders/42/confirmation"
        }
        let body = try req.content.decode(CheckoutBody.self)

        // Process order confirmation (omitted for brevity)
        req.logger.info("Order \(body.orderId) confirmed")

        // Attacker input: "https://phishing.example.com/fake-order-confirm?id=42"
        return req.redirect(to: body.returnUrl)
    }

    // VULN 3: Open Redirect using OAuth `state` parameter as redirect target
    // The OAuth state parameter is round-tripped through the provider and used
    // directly as the post-authentication redirect destination. An attacker can
    // inject a crafted state value to redirect after OAuth login to an arbitrary URL.
    func oauthCallback(req: Request) throws -> Response {
        guard let code = req.query[String.self, at: "code"],
              let state = req.query[String.self, at: "state"] else {
            throw Abort(.badRequest, reason: "Missing OAuth parameters")
        }

        // Exchange code for token (omitted)
        req.logger.info("OAuth code received: \(code)")

        // `state` was set by the client before redirect to the OAuth provider;
        // it is now used as the redirect target without validation.
        // Attacker crafts OAuth initiation URL with state=https://evil.example.com
        return req.redirect(to: state)
    }
}
