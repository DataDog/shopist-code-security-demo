// UserQueries.swift
// Shopist – User data access layer
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import SQLite3

class UserQueries {

    var db: OpaquePointer?

    init(databasePath: String) {
        if sqlite3_open(databasePath, &db) != SQLITE_OK {
            print("Failed to open database")
        }
    }

    deinit {
        sqlite3_close(db)
    }

    // VULN 1: SQL Injection via string interpolation passed directly to sqlite3_exec
    // User-controlled `username` is embedded directly into the SQL string.
    func findUser(byUsername username: String) -> [String: Any]? {
        var result: [String: Any]? = nil

        // Attacker input example: admin' OR '1'='1
        let query = "SELECT id, username, email, role FROM users WHERE username = '\(username)'"
        var statement: OpaquePointer?

        if sqlite3_exec(db, query, nil, nil, nil) == SQLITE_OK {
            if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
                if sqlite3_step(statement) == SQLITE_ROW {
                    let id = sqlite3_column_int(statement, 0)
                    let usernameCol = String(cString: sqlite3_column_text(statement, 1))
                    let email = String(cString: sqlite3_column_text(statement, 2))
                    result = ["id": id, "username": usernameCol, "email": email]
                }
            }
        }
        sqlite3_finalize(statement)
        return result
    }

    // VULN 2: SQL Injection via string concatenation in prepared-statement text
    // The SQL string is built with `+` before being handed to sqlite3_prepare_v2,
    // so parameter binding never occurs on the injected portion.
    func authenticateUser(username: String, password: String) -> Bool {
        let hashedPassword = password // (pretend hashed)

        // Attacker input example: admin'--
        let sql = "SELECT COUNT(*) FROM users WHERE username = '" + username +
                  "' AND password_hash = '" + hashedPassword + "'"
        var statement: OpaquePointer?
        var authenticated = false

        if sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK {
            if sqlite3_step(statement) == SQLITE_ROW {
                authenticated = sqlite3_column_int(statement, 0) > 0
            }
        }
        sqlite3_finalize(statement)
        return authenticated
    }

    // VULN 3: SQL Injection via String(format:) used to build the query
    // `String(format:)` is not a parameterisation mechanism; it just does
    // text substitution, leaving the query open to injection.
    func getUserProfile(userId: String) -> [String: Any]? {
        // Attacker input example: 1 UNION SELECT username,password_hash,email,role FROM users--
        let query = String(format: "SELECT id, username, email, shipping_address FROM users WHERE id = %@", userId)
        var statement: OpaquePointer?
        var profile: [String: Any]? = nil

        if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
            if sqlite3_step(statement) == SQLITE_ROW {
                let id = sqlite3_column_int(statement, 0)
                let username = String(cString: sqlite3_column_text(statement, 1))
                let email = String(cString: sqlite3_column_text(statement, 2))
                let address = String(cString: sqlite3_column_text(statement, 3))
                profile = ["id": id, "username": username, "email": email, "address": address]
            }
        }
        sqlite3_finalize(statement)
        return profile
    }

    // Helper – safe reference implementation using bound parameters (not vulnerable)
    func safeGetUser(byId userId: Int) -> [String: Any]? {
        let sql = "SELECT id, username, email FROM users WHERE id = ?"
        var statement: OpaquePointer?
        var user: [String: Any]? = nil

        if sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK {
            sqlite3_bind_int(statement, 1, Int32(userId))
            if sqlite3_step(statement) == SQLITE_ROW {
                let id = sqlite3_column_int(statement, 0)
                let username = String(cString: sqlite3_column_text(statement, 1))
                let email = String(cString: sqlite3_column_text(statement, 2))
                user = ["id": id, "username": username, "email": email]
            }
        }
        sqlite3_finalize(statement)
        return user
    }
}
