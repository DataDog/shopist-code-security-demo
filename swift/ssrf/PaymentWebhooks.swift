// PaymentWebhooks.swift
// Shopist – Payment provider webhook dispatcher and shipping tracker
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct PaymentWebhooksController: RouteCollection {

    func boot(routes: RoutesBuilder) throws {
        let payments = routes.grouped("payments")
        payments.post("register-webhook", use: registerWebhook)
        payments.post("enrich-product-image", use: fetchProductImage)
        payments.post("track-shipment", use: trackShipment)
    }

    // VULN 1: SSRF via user-controlled webhook URL passed to URLSession
    // The merchant supplies a `webhookUrl` in their account settings; the server
    // makes an outbound request to that URL when payment events occur. No allowlist
    // or scheme/host validation is performed, so an attacker can point the URL at
    // internal services (e.g., http://169.254.169.254/latest/meta-data/).
    func registerWebhook(req: Request) async throws -> HTTPStatus {
        struct WebhookConfig: Content {
            var webhookUrl: String   // e.g., "https://merchant.example.com/webhook"
            var secret: String
        }
        let config = try req.content.decode(WebhookConfig.self)

        // Attacker input: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        guard let url = URL(string: config.webhookUrl) else {
            throw Abort(.badRequest, reason: "Invalid webhook URL")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let testPayload = try JSONEncoder().encode(["event": "ping", "source": "shopist"])
        request.httpBody = testPayload

        let (_, response) = try await URLSession.shared.data(for: request)
        let httpResponse = response as? HTTPURLResponse
        req.logger.info("Webhook ping to \(config.webhookUrl) returned \(httpResponse?.statusCode ?? 0)")

        return .ok
    }

    // VULN 2: SSRF via user-supplied product image URL fetched by the server
    // The `imageUrl` field is taken from a product-import CSV row; the server
    // fetches the image to resize it for the catalogue. No host allowlist is enforced,
    // enabling requests to RFC-1918 addresses or file:// URLs on some platforms.
    func fetchProductImage(req: Request) async throws -> Response {
        struct ImageRequest: Content {
            var imageUrl: String   // e.g., "https://cdn.supplier.com/products/123.jpg"
            var productId: Int
        }
        let body = try req.content.decode(ImageRequest.self)

        // Attacker input: "http://10.0.0.1/admin" or "file:///etc/passwd"
        guard let url = URL(string: body.imageUrl) else {
            throw Abort(.badRequest, reason: "Invalid image URL")
        }

        let (imageData, _) = try await URLSession.shared.data(from: url)
        // Image would be resized and stored; here we just echo size
        return Response(status: .ok, body: .init(string: "Fetched \(imageData.count) bytes for product \(body.productId)"))
    }

    // VULN 3: SSRF via user-controlled carrier tracking URL
    // The carrier URL is stored in the orders table (set at checkout); the server
    // fetches live tracking data from it. An attacker who can set their order's
    // carrier URL can pivot to internal infrastructure.
    func trackShipment(req: Request) async throws -> Response {
        struct TrackRequest: Content {
            var orderId: Int
            var carrierUrl: String   // e.g., "https://api.fedex.com/track?id=123"
        }
        let body = try req.content.decode(TrackRequest.self)

        // Attacker input: "http://internal-admin.shopist.local/debug/env"
        let trackingRequest = URLRequest(url: URL(string: body.carrierUrl)!)
        let (data, _) = try await URLSession.shared.data(for: trackingRequest)
        let trackingInfo = String(data: data, encoding: .utf8) ?? ""

        return Response(status: .ok, body: .init(string: trackingInfo))
    }
}
