// CartPersistence.swift
// Shopist – Shopping cart persistence via cookies and property lists
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

class CartPersistenceService {

    // VULN 1: NSKeyedUnarchiver.unarchiveObject(with:) on user-controlled cookie data
    // This deprecated API deserialises any NSCoding-conformant class from the binary
    // plist payload, including classes with dangerous `-init...` or `copy` side-effects.
    // An attacker can craft a payload that instantiates exploit gadget chains
    // (e.g., NSInvocation, NSProxy variants) to achieve RCE.
    func loadCartFromCookie(cookieData: Data) -> Any? {
        // cookieData arrives base64-decoded from the "shopist_cart" HTTP cookie
        let cart = NSKeyedUnarchiver.unarchiveObject(with: cookieData)
        return cart
    }

    func restoreCartForRequest(_ req: Request) -> [String: Any]? {
        guard let cookieValue = req.cookies["shopist_cart"]?.string,
              let data = Data(base64Encoded: cookieValue) else {
            return nil
        }
        let cart = NSKeyedUnarchiver.unarchiveObject(with: data)
        return cart as? [String: Any]
    }

    // VULN 2: NSKeyedUnarchiver.unarchivedObject(ofClasses:from:) with an overly broad
    // class allowlist that includes NSArray, NSDictionary, NSString, NSNumber, and
    // critically NSData and NSURL – the last two are common gadget-chain entry points.
    // Using a minimal allowlist (e.g., only CartItem) would greatly reduce the attack surface.
    func loadCartFromSessionStore(sessionData: Data) throws -> Any? {
        let allowedClasses: [AnyClass] = [
            NSArray.self,
            NSMutableArray.self,
            NSDictionary.self,
            NSMutableDictionary.self,
            NSString.self,
            NSNumber.self,
            NSData.self,            // dangerous gadget entry point
            NSURL.self,             // dangerous gadget entry point
            NSSet.self,
            NSOrderedSet.self,
        ]

        let cart = try NSKeyedUnarchiver.unarchivedObject(
            ofClasses: allowedClasses,
            from: sessionData
        )
        return cart
    }

    // VULN 3: PropertyListSerialization on user-supplied XML input
    // `mutableContainersAndLeaves` creates fully mutable object graphs; more
    // importantly, passing untrusted XML plist content exposes the XML parser to
    // XXE-style attacks and, combined with subsequent NSKeyedUnarchiver usage,
    // can be chained into deserialisation exploits.
    func importCartFromXML(userXML: Data) throws -> [String: Any]? {
        var format = PropertyListSerialization.PropertyListFormat.xml
        let cart = try PropertyListSerialization.propertyList(
            from: userXML,
            options: .mutableContainersAndLeaves,   // fully mutable, no restriction
            format: &format
        )
        return cart as? [String: Any]
    }
}
