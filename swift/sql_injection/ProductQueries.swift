// ProductQueries.swift
// Shopist – Product catalogue data access layer
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import SQLite3

class ProductQueries {

    var db: OpaquePointer?

    init(databasePath: String) {
        if sqlite3_open(databasePath, &db) != SQLITE_OK {
            print("Failed to open database at \(databasePath)")
        }
    }

    deinit {
        sqlite3_close(db)
    }

    // VULN 1: SQL Injection via string interpolation in product search
    // The `searchTerm` value comes directly from a query parameter and is
    // interpolated without escaping or binding.
    func searchProducts(searchTerm: String) -> [[String: Any]] {
        var products: [[String: Any]] = []

        // Attacker input: ' UNION SELECT id,username,password_hash,4,5 FROM users--
        let query = "SELECT id, name, description, price, stock FROM products WHERE name LIKE '%\(searchTerm)%' OR description LIKE '%\(searchTerm)%'"
        var statement: OpaquePointer?

        if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
            while sqlite3_step(statement) == SQLITE_ROW {
                let id = sqlite3_column_int(statement, 0)
                let name = String(cString: sqlite3_column_text(statement, 1))
                let description = String(cString: sqlite3_column_text(statement, 2))
                let price = sqlite3_column_double(statement, 3)
                let stock = sqlite3_column_int(statement, 4)
                products.append(["id": id, "name": name, "description": description, "price": price, "stock": stock])
            }
        }
        sqlite3_finalize(statement)
        return products
    }

    // VULN 2: SQL Injection via string concatenation for price-range filter
    // `minPrice` and `maxPrice` arrive as raw strings from the request; they are
    // concatenated directly into the SQL without validation or binding.
    func filterProductsByPrice(minPrice: String, maxPrice: String) -> [[String: Any]] {
        var products: [[String: Any]] = []

        // Attacker input for minPrice: 0 OR 1=1--
        let sql = "SELECT id, name, price, category_id FROM products WHERE price >= " + minPrice +
                  " AND price <= " + maxPrice + " AND is_active = 1"
        var statement: OpaquePointer?

        if sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK {
            while sqlite3_step(statement) == SQLITE_ROW {
                let id = sqlite3_column_int(statement, 0)
                let name = String(cString: sqlite3_column_text(statement, 1))
                let price = sqlite3_column_double(statement, 2)
                let categoryId = sqlite3_column_int(statement, 3)
                products.append(["id": id, "name": name, "price": price, "categoryId": categoryId])
            }
        }
        sqlite3_finalize(statement)
        return products
    }

    // VULN 3: SQL Injection via String(format:) in category query
    // The category slug is a user-supplied string passed as a %@ format argument –
    // String(format:) performs plain text substitution, not parameterisation.
    func getProductsByCategory(categorySlug: String) -> [[String: Any]] {
        var products: [[String: Any]] = []

        // Attacker input: electronics' OR '1'='1
        let query = String(format: "SELECT p.id, p.name, p.price, p.image_url FROM products p JOIN categories c ON p.category_id = c.id WHERE c.slug = '%@' AND p.is_active = 1", categorySlug)
        var statement: OpaquePointer?

        if sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK {
            while sqlite3_step(statement) == SQLITE_ROW {
                let id = sqlite3_column_int(statement, 0)
                let name = String(cString: sqlite3_column_text(statement, 1))
                let price = sqlite3_column_double(statement, 2)
                let imageUrl = String(cString: sqlite3_column_text(statement, 3))
                products.append(["id": id, "name": name, "price": price, "imageUrl": imageUrl])
            }
        }
        sqlite3_finalize(statement)
        return products
    }
}
