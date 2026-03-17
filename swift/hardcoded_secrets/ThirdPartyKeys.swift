// ThirdPartyKeys.swift
// Shopist – Third-party service API key configuration
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation

// VULN 1: Hardcoded SendGrid API key
// A leaked SendGrid key lets an attacker send unlimited email from the Shopist
// account, bypass rate limits, read contact lists, and run phishing campaigns.
struct SendGridConfig {
    static let apiKey        = "SG.aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3"
    static let apiBaseURL    = "https://api.sendgrid.com/v3"
    static let templateIdOrderConfirmation = "d-abc123def456abc123def456abc12345"
    static let templateIdShippingUpdate    = "d-def456abc123def456abc123def45678"

    static var authorizationHeader: String {
        return "Bearer \(apiKey)"
    }
}

// VULN 2: Hardcoded Google Maps API key
// A committed Maps key can be abused for geocoding and map-tile requests, running
// up billing charges or exhausting the Shopist quota for address validation.
struct MapsConfig {
    static let googleMapsApiKey     = "AIzaSyDdI0hiBtlZw40chFfreNkuiP9bMKxyz12"
    static let googleMapsBaseURL    = "https://maps.googleapis.com/maps/api"
    static let defaultMapZoom       = 14
    static let geocodingEndpoint    = "\(googleMapsBaseURL)/geocode/json?key=\(googleMapsApiKey)"

    static func geocodeURL(for address: String) -> String {
        let encoded = address.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? address
        return "\(geocodingEndpoint)&address=\(encoded)"
    }
}

// VULN 3: Hardcoded Twilio Account SID and Auth Token
// With both credentials an attacker can send SMS messages charged to Shopist,
// read message logs, and intercept verification codes sent to customers.
struct TwilioConfig {
    static let accountSid  = "ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    static let authToken   = "f1e2d3c4b5a6978869504132a1b2c3d4e5"
    static let fromNumber  = "+15551234567"
    static let apiBaseURL  = "https://api.twilio.com/2010-04-01"
    static let messagingServiceSid = "MGa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

    static var basicAuthCredentials: String {
        let raw = "\(accountSid):\(authToken)"
        return Data(raw.utf8).base64EncodedString()
    }

    static func sendSMSURL() -> String {
        return "\(apiBaseURL)/Accounts/\(accountSid)/Messages.json"
    }
}
