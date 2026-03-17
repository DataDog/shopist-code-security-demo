// ProductEnrichment.swift
// Shopist – Product data enrichment from external sources
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct ProductEnrichmentController: RouteCollection {

    func boot(routes: RoutesBuilder) throws {
        let enrich = routes.grouped("products", "enrich")
        enrich.post("import", use: importProductData)
        enrich.get("rss-feed", use: fetchRssFeed)
        enrich.post("supplier-api", use: fetchSupplierData)
    }

    // VULN 1: SSRF via user-supplied data source URL fetched with URLSession
    // `sourceUrl` is provided by the merchant in a product-import request. The server
    // fetches the remote data with no allowlist validation, enabling requests to
    // cloud metadata endpoints, internal services, or arbitrary TCP ports.
    func importProductData(req: Request) async throws -> Response {
        struct ImportRequest: Content {
            var sourceUrl: String   // e.g., "https://supplier.example.com/feed.json"
            var categoryId: Int
        }
        let body = try req.content.decode(ImportRequest.self)

        // Attacker input: "http://169.254.169.254/latest/meta-data/iam/security-credentials/shopist-role"
        guard let url = URL(string: body.sourceUrl) else {
            throw Abort(.badRequest, reason: "Invalid source URL")
        }

        let (data, response) = try await URLSession.shared.data(from: url)
        let httpResponse = response as? HTTPURLResponse
        let body2 = String(data: data, encoding: .utf8) ?? ""

        req.logger.info("Fetched \(data.count) bytes from \(body.sourceUrl), status \(httpResponse?.statusCode ?? 0)")
        return Response(status: .ok, body: .init(string: "Imported \(body2.count) chars into category \(body.categoryId)"))
    }

    // VULN 2: SSRF via RSS feed URL taken directly from a query parameter
    // The `feedUrl` query param lets the client specify which RSS feed to aggregate.
    // No scheme check, no host allowlist, and no redirect following limit are applied.
    func fetchRssFeed(req: Request) async throws -> Response {
        guard let feedUrl = req.query[String.self, at: "feedUrl"] else {
            throw Abort(.badRequest, reason: "Missing feedUrl parameter")
        }

        // Attacker input: "http://internal-redis.shopist.local:6379/" or
        //                 "gopher://internal-redis.shopist.local:6379/_FLUSHALL"
        let urlRequest = URLRequest(url: URL(string: feedUrl)!)
        let (data, _) = try await URLSession.shared.data(for: urlRequest)

        let xml = String(data: data, encoding: .utf8) ?? ""
        // Parse and return feed items...
        return Response(status: .ok, body: .init(string: xml))
    }

    // VULN 3: SSRF via API base URL assembled from user-supplied string concatenation
    // The merchant can set a custom `apiBase` (e.g., their supplier API root); the
    // server appends a fixed path and fetches it. An attacker can supply an internal
    // base URL to scan the internal network through the Shopist server.
    func fetchSupplierData(req: Request) async throws -> Response {
        struct SupplierRequest: Content {
            var apiBase: String     // e.g., "https://api.supplier.example.com/v2"
            var productSku: String
        }
        let body = try req.content.decode(SupplierRequest.self)

        // Attacker input for apiBase: "http://10.0.0.50:8080"
        // Results in request to: "http://10.0.0.50:8080/products/ABC-123"
        let fullUrl = body.apiBase + "/products/" + body.productSku
        guard let url = URL(string: fullUrl) else {
            throw Abort(.badRequest, reason: "Invalid API URL")
        }

        var request = URLRequest(url: url)
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, _) = try await URLSession.shared.data(for: request)
        return Response(status: .ok, body: .init(data: data))
    }
}
