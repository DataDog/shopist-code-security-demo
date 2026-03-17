// OrderQueries.swift
// Shopist – Order management data access layer
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import SQLite3

class OrderQueries {

    var db: OpaquePointer?

    init(databasePath: String) {
        if sqlite3_open(databasePath, &db) != SQLITE_OK {
            print("Failed to open database at \(databasePath)")
        }
    }

    deinit {
        sqlite3_close(db)
    }

    // VULN 1: SQL Injection via string interpolation in order-status query
    // `status` is taken straight from the HTTP request body and embedded into SQL.
    func getOrdersByStatus(userId: Int, status: String) -> [[String: Any]] {
        var orders: [[String: Any]] = []

        // Attacker input: shipped' OR '1'='1
        let query = "SELECT id, total_amount, created_at, tracking_number FROM orders WHERE user_id = \(userId) AND status = '\(status)'"
        var statement: OpaquePointer?

        if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
            while sqlite3_step(statement) == SQLITE_ROW {
                let id = sqlite3_column_int(statement, 0)
                let total = sqlite3_column_double(statement, 1)
                let createdAt = String(cString: sqlite3_column_text(statement, 2))
                let tracking = String(cString: sqlite3_column_text(statement, 3))
                orders.append(["id": id, "total": total, "createdAt": createdAt, "tracking": tracking])
            }
        }
        sqlite3_finalize(statement)
        return orders
    }

    // VULN 2: SQL Injection via string concatenation for date-range filter
    // `startDate` and `endDate` are raw strings from query parameters; no
    // sanitisation or binding is performed before concatenation.
    func getOrdersInDateRange(startDate: String, endDate: String) -> [[String: Any]] {
        var orders: [[String: Any]] = []

        // Attacker input for startDate: 2024-01-01' OR '1'='1
        let sql = "SELECT o.id, o.user_id, o.total_amount, o.status FROM orders o " +
                  "WHERE o.created_at >= '" + startDate + "' AND o.created_at <= '" + endDate + "'"
        var statement: OpaquePointer?

        if sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK {
            while sqlite3_step(statement) == SQLITE_ROW {
                let id = sqlite3_column_int(statement, 0)
                let userId = sqlite3_column_int(statement, 1)
                let total = sqlite3_column_double(statement, 2)
                let status = String(cString: sqlite3_column_text(statement, 3))
                orders.append(["id": id, "userId": userId, "total": total, "status": status])
            }
        }
        sqlite3_finalize(statement)
        return orders
    }

    // VULN 3: SQL Injection via String(format:) in admin-search query
    // Admin search accepts a free-text `searchTerm` from the dashboard; String(format:)
    // substitutes the value as plain text, not a bound parameter.
    func adminSearchOrders(searchTerm: String, limit: Int) -> [[String: Any]] {
        var orders: [[String: Any]] = []

        // Attacker input: %' UNION SELECT username,password_hash,email,role FROM users--
        let query = String(
            format: "SELECT o.id, u.username, o.total_amount, o.status FROM orders o JOIN users u ON o.user_id = u.id WHERE u.username LIKE '%%%@%%' OR o.id LIKE '%%%@%%' LIMIT %d",
            searchTerm, searchTerm, limit
        )
        var statement: OpaquePointer?

        if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
            while sqlite3_step(statement) == SQLITE_ROW {
                let id = sqlite3_column_int(statement, 0)
                let username = String(cString: sqlite3_column_text(statement, 1))
                let total = sqlite3_column_double(statement, 2)
                let status = String(cString: sqlite3_column_text(statement, 3))
                orders.append(["id": id, "username": username, "total": total, "status": status])
            }
        }
        sqlite3_finalize(statement)
        return orders
    }
}
