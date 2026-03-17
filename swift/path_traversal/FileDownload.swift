// FileDownload.swift
// Shopist – Product asset / invoice download handler
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct FileDownloadController: RouteCollection {

    let baseDir = "/var/shopist/downloads/"

    func boot(routes: RoutesBuilder) throws {
        let files = routes.grouped("files")
        files.get("download", use: downloadFile)
        files.get("invoice", use: downloadInvoice)
        files.get("asset", use: serveAsset)
    }

    // VULN 1: Path Traversal via direct string concatenation without canonicalization
    // `fileName` comes from the query string; joining it to `baseDir` with `+` allows
    // `../../etc/passwd` style traversal. FileManager does not resolve symlinks or
    // normalise `..` segments before reading.
    func downloadFile(req: Request) throws -> Response {
        guard let fileName = req.query[String.self, at: "file"] else {
            throw Abort(.badRequest, reason: "Missing file parameter")
        }

        // Attacker input example: ../../etc/passwd  or  ../../../private/var/db/auth.db
        let filePath = baseDir + fileName
        guard let data = FileManager.default.contents(atPath: filePath) else {
            throw Abort(.notFound)
        }

        return Response(
            status: .ok,
            headers: HTTPHeaders([("Content-Disposition", "attachment; filename=\"\(fileName)\"")]),
            body: .init(data: data)
        )
    }

    // VULN 2: Path Traversal via URL(fileURLWithPath:).appendingPathComponent without validation
    // `appendingPathComponent` does not prevent traversal when the component begins with
    // `/` (absolute) or contains `..` sequences, especially before iOS 16 / macOS 13.
    func downloadInvoice(req: Request) throws -> Response {
        guard let userFile = req.query[String.self, at: "invoice"] else {
            throw Abort(.badRequest, reason: "Missing invoice parameter")
        }

        let invoicesDir = "/var/shopist/invoices/"
        // No canonicalization or prefix check performed
        let fileURL = URL(fileURLWithPath: invoicesDir).appendingPathComponent(userFile)

        guard let data = try? Data(contentsOf: fileURL) else {
            throw Abort(.notFound, reason: "Invoice not found")
        }

        return Response(
            status: .ok,
            headers: HTTPHeaders([("Content-Type", "application/pdf")]),
            body: .init(data: data)
        )
    }

    // VULN 3: Path Traversal by reading file at a fully user-controlled path
    // The `path` query parameter can point to any absolute path on the filesystem.
    // No allowlist, no prefix enforcement, and no permission check.
    func serveAsset(req: Request) throws -> Response {
        guard let relativePath = req.query[String.self, at: "path"] else {
            throw Abort(.badRequest, reason: "Missing path parameter")
        }

        let assetsBase = "/var/shopist/assets/"
        // Attacker can supply an absolute path or traverse with ../
        let fullPath = assetsBase + relativePath

        guard FileManager.default.fileExists(atPath: fullPath) else {
            throw Abort(.notFound)
        }

        let data = FileManager.default.contents(atPath: fullPath) ?? Data()
        let mimeType = mimeTypeForExtension(fullPath)

        return Response(
            status: .ok,
            headers: HTTPHeaders([("Content-Type", mimeType)]),
            body: .init(data: data)
        )
    }

    // Minimal MIME helper (not security-relevant)
    private func mimeTypeForExtension(_ path: String) -> String {
        switch (path as NSString).pathExtension.lowercased() {
        case "png": return "image/png"
        case "jpg", "jpeg": return "image/jpeg"
        case "pdf": return "application/pdf"
        default: return "application/octet-stream"
        }
    }
}
