// SessionHandling.swift
// Shopist – Server-side session deserialisation
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

class SessionHandlingService {

    // VULN 1: NSPropertyListSerialization deserialising a user-supplied plist
    // The raw plist bytes come from an HTTP header or POST body; an attacker can
    // supply a binary plist that triggers unexpected object instantiation or
    // exploits parser bugs. No schema validation is performed after deserialisation.
    func deserializeSessionPlist(plistData: Data) throws -> [String: Any] {
        var format = PropertyListSerialization.PropertyListFormat.binary

        // plistData originates from the "X-Shopist-Session" request header (base64-decoded)
        let sessionDict = try PropertyListSerialization.propertyList(
            from: plistData,
            options: [],
            format: &format
        )

        guard let dict = sessionDict as? [String: Any] else {
            throw Abort(.badRequest, reason: "Invalid session format")
        }
        return dict
    }

    func loadSession(from req: Request) throws -> [String: Any] {
        guard let headerValue = req.headers.first(name: "X-Shopist-Session"),
              let plistData = Data(base64Encoded: headerValue) else {
            throw Abort(.unauthorized)
        }
        return try deserializeSessionPlist(plistData: plistData)
    }

    // VULN 2: JSONDecoder used with a dynamically typed, type-tagged payload
    // The session JSON contains a `__type` key that the server trusts to select
    // the concrete decoding type from a registry. Sending an unexpected type name
    // can instantiate unintended Decodable types, potentially triggering side-effects
    // in their `init(from:)` implementations.
    func deserializeTypedSession(jsonData: Data) throws -> Any {
        struct TypeTaggedSession: Decodable {
            let __type: String
            let payload: Data   // raw JSON for the actual object
        }

        let typeRegistry: [String: Decodable.Type] = [
            "UserSession": UserSession.self,
            "GuestSession": GuestSession.self,
            "AdminSession": AdminSession.self,   // attacker can request AdminSession
        ]

        let wrapper = try JSONDecoder().decode(TypeTaggedSession.self, from: jsonData)
        guard let targetType = typeRegistry[wrapper.__type] else {
            throw Abort(.badRequest, reason: "Unknown session type")
        }

        // Decodes wrapper.payload as the attacker-chosen type
        return try JSONDecoder().decode(targetType, from: wrapper.payload)
    }

    // VULN 3: Unsafe unarchiving of base64-decoded cookie with NSKeyedUnarchiver
    // The session cookie value is base64-decoded and passed directly to
    // NSKeyedUnarchiver without class restrictions, allowing gadget-chain exploitation.
    func loadSessionFromCookie(req: Request) -> [String: Any]? {
        guard let cookieValue = req.cookies["shopist_session"]?.string,
              let archivedData = Data(base64Encoded: cookieValue) else {
            return nil
        }

        // NSKeyedUnarchiver with no class restriction – accepts any NSCoding class
        let session = try? NSKeyedUnarchiver.unarchivedObject(
            ofClasses: [NSDictionary.self, NSArray.self, NSString.self,
                        NSNumber.self, NSData.self, NSDate.self, NSURL.self],
            from: archivedData
        )
        return session as? [String: Any]
    }
}

// Supporting session types referenced above
struct UserSession: Codable {
    let userId: Int
    let username: String
    let role: String
}

struct GuestSession: Codable {
    let sessionId: String
    let cartId: String
}

struct AdminSession: Codable {
    let userId: Int
    let username: String
    let role: String
    let adminLevel: Int
    let permissions: [String]
}
