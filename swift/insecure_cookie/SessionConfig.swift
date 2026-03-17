// SessionConfig.swift
// Shopist – HTTP session and cookie configuration
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

// VULN 1: Session cookie set with isSecure: false
// A cookie without the Secure flag is transmitted over plain HTTP as well as
// HTTPS. An attacker performing a network interception (coffee-shop Wi-Fi, HTTP
// downgrade) can steal the session token in cleartext.
struct InsecureCookieSessionManager {

    func createSessionCookie(token: String) -> HTTPCookiePropertyKey {
        // HTTPCookieStorage API – isSecure is explicitly false
        let cookieProperties: [HTTPCookiePropertyKey: Any] = [
            .name:    "shopist_session",
            .value:   token,
            .domain:  "shopist.io",
            .path:    "/",
            .expires: Date(timeIntervalSinceNow: 86400),
            .secure:  false,    // VULN: cookie sent over HTTP too
        ]
        let cookie = HTTPCookie(properties: cookieProperties)!
        HTTPCookieStorage.shared.setCookie(cookie)
        return .name
    }

    // Vapor variant – Secure flag omitted from HTTPCookies.Value
    func setVaporSessionCookie(response: inout Response, token: String) {
        response.cookies["shopist_session"] = HTTPCookies.Value(
            string: token,
            expires: Date(timeIntervalSinceNow: 86400),
            maxAge: nil,
            domain: "shopist.io",
            path: "/",
            isSecure: false,    // VULN: should be true in production
            isHTTPOnly: true,
            sameSite: .lax
        )
    }
}

// VULN 2: Authentication cookie set with isHTTPOnly: false
// A cookie without the HttpOnly flag is accessible from JavaScript via
// document.cookie. A single XSS vulnerability anywhere on the domain is
// sufficient for an attacker's script to exfiltrate the session token.
struct InsecureHTTPOnlyCookieManager {

    func createAuthCookie(userId: Int, token: String) -> HTTPCookie? {
        let cookieProperties: [HTTPCookiePropertyKey: Any] = [
            .name:     "shopist_auth",
            .value:    token,
            .domain:   "shopist.io",
            .path:     "/",
            .expires:  Date(timeIntervalSinceNow: 3600 * 8),
            // .secure is also missing here (implicit false)
            // httpOnly is not set – defaults to false in HTTPCookieStorage
        ]
        return HTTPCookie(properties: cookieProperties)
    }

    // Vapor variant – isHTTPOnly left false
    func setVaporAuthCookie(response: inout Response, token: String) {
        response.cookies["shopist_auth"] = HTTPCookies.Value(
            string: token,
            expires: Date(timeIntervalSinceNow: 3600 * 8),
            maxAge: nil,
            domain: "shopist.io",
            path: "/",
            isSecure: true,
            isHTTPOnly: false,  // VULN: accessible from JavaScript
            sameSite: .lax
        )
    }
}

// VULN 3: Vapor session cookie set with no Secure flag and no HttpOnly flag
// Neither the Secure nor HttpOnly attribute is specified in the HTTPCookies.Value
// initialiser, so both default to false in the Vapor response. This exposes the
// session token to both network sniffing and XSS-based theft simultaneously.
struct BareVaporSessionCookieHandler {

    func attachSessionCookie(to response: inout Response, sessionToken: String) {
        // No isSecure, no isHTTPOnly, no sameSite – fully exposed cookie
        response.cookies["session"] = HTTPCookies.Value(string: sessionToken)
    }

    func setCartCookie(response: inout Response, cartId: String) {
        // Cart ID leaks browsing behaviour; isHTTPOnly: false lets JS read it
        response.cookies["shopist_cart"] = HTTPCookies.Value(
            string: cartId,
            expires: Date(timeIntervalSinceNow: 86400 * 30),
            maxAge: nil,
            domain: "shopist.io",
            path: "/",
            isSecure: false,    // VULN: sent over HTTP
            isHTTPOnly: false,  // VULN: readable by JavaScript
            sameSite: nil       // VULN: no SameSite protection
        )
    }

    func setRememberMeCookie(response: inout Response, token: String) {
        // Long-lived remember-me token with no security attributes
        response.cookies["shopist_remember"] = HTTPCookies.Value(
            string: token,
            expires: Date(timeIntervalSinceNow: 86400 * 365),
            maxAge: nil,
            domain: "shopist.io",
            path: "/",
            isSecure: false,    // VULN: year-long token sent over HTTP
            isHTTPOnly: false,  // VULN: readable by JavaScript
            sameSite: nil
        )
    }
}
