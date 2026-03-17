// StaticFiles.swift
// Shopist – Static file / directory serving handler
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct StaticFilesController: RouteCollection {

    let webRoot = "/var/shopist/public/"

    func boot(routes: RoutesBuilder) throws {
        routes.get("static", ":file", use: serveStaticFile)
        routes.get("browse", use: listDirectory)
        routes.get("resource", use: serveResource)
    }

    // VULN 1: Path Traversal by serving a file at baseDir + request path parameter
    // `:file` is a Vapor path parameter that captures whatever the client provides,
    // including `..%2F..%2Fetc%2Fpasswd`. The value is appended to `webRoot` with no
    // normalisation, allowing directory traversal.
    func serveStaticFile(req: Request) throws -> Response {
        guard let file = req.parameters.get("file") else {
            throw Abort(.badRequest)
        }

        // Attacker input example: ../../etc/passwd  (URL-decoded by Vapor)
        let filePath = webRoot + file
        guard let data = FileManager.default.contents(atPath: filePath) else {
            throw Abort(.notFound)
        }

        return Response(
            status: .ok,
            body: .init(data: data)
        )
    }

    // VULN 2: Path Traversal enabling directory listing with user-controlled dir
    // The `dir` query parameter specifies which subdirectory to list; by supplying
    // `../../` the attacker can enumerate arbitrary parts of the filesystem.
    func listDirectory(req: Request) throws -> Response {
        guard let dir = req.query[String.self, at: "dir"] else {
            throw Abort(.badRequest, reason: "Missing dir parameter")
        }

        // Attacker input example: ../../private/var
        let targetDir = webRoot + dir

        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: targetDir) else {
            throw Abort(.notFound, reason: "Directory not found or not accessible")
        }

        let listing = entries.joined(separator: "\n")
        return Response(status: .ok, body: .init(string: listing))
    }

    // VULN 3: Path Traversal via Data(contentsOf:) on a root + user path
    // `relativePath` is taken from the query string and concatenated to `root`
    // before being wrapped in a URL. There is no canonicalization, no `hasPrefix`
    // check after resolution, and no symlink check.
    func serveResource(req: Request) throws -> Response {
        guard let relativePath = req.query[String.self, at: "resource"] else {
            throw Abort(.badRequest, reason: "Missing resource parameter")
        }

        let root = "/var/shopist/public/"
        // Attacker input example: ../invoices/order_99999.pdf
        let fullURL = URL(fileURLWithPath: root + relativePath)

        guard let data = try? Data(contentsOf: fullURL) else {
            throw Abort(.notFound, reason: "Resource not found")
        }

        return Response(
            status: .ok,
            headers: HTTPHeaders([("Content-Type", "application/octet-stream")]),
            body: .init(data: data)
        )
    }
}
