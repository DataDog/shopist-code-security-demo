// FileUpload.swift
// Shopist – Product image / document upload handler
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct FileUploadController: RouteCollection {

    let uploadDir = "/var/shopist/uploads/"

    func boot(routes: RoutesBuilder) throws {
        let upload = routes.grouped("upload")
        upload.post("product-image", use: uploadProductImage)
        upload.post("extract-zip", use: extractZip)
        upload.post("document", use: uploadDocument)
    }

    // VULN 1: Path Traversal when writing uploaded data to a user-specified path
    // `filename` is taken directly from the multipart Content-Disposition header or
    // query parameter; writing to `uploadDir + userFilename` without normalisation
    // allows the attacker to overwrite arbitrary files (e.g., ../../app/config.swift).
    func uploadProductImage(req: Request) async throws -> HTTPStatus {
        struct UploadPayload: Content {
            var file: File
            var filename: String
        }
        let payload = try req.content.decode(UploadPayload.self)

        // Attacker supplies filename: ../../app/config.swift
        let destinationPath = uploadDir + payload.filename
        let destinationURL = URL(fileURLWithPath: destinationPath)

        var buffer = payload.file.data
        let data = buffer.readData(length: buffer.readableBytes) ?? Data()
        try data.write(to: destinationURL)

        return .ok
    }

    // VULN 2: Path Traversal when extracting a ZIP archive to a user-controlled directory
    // The target directory (`extractTo`) is assembled from user input; a maliciously
    // crafted ZIP with `../` path entries (Zip Slip) writes files outside the intended
    // extraction root.
    func extractZip(req: Request) async throws -> HTTPStatus {
        struct ZipPayload: Content {
            var archive: File
            var extractTo: String   // user-supplied target directory
        }
        let payload = try req.content.decode(ZipPayload.self)

        // Attacker supplies extractTo: ../../etc/cron.d
        let targetDir = uploadDir + payload.extractTo

        // Simulate writing each entry from the archive to the user-specified directory
        var buffer = payload.archive.data
        let archiveData = buffer.readData(length: buffer.readableBytes) ?? Data()

        // In a real implementation the ZIP entries would be iterated; each entry path
        // is appended to targetDir without checking that the result stays inside targetDir.
        let archivePath = targetDir + "/archive.zip"
        try archiveData.write(to: URL(fileURLWithPath: archivePath))

        return .ok
    }

    // VULN 3: Path Traversal by writing a document to a fully user-controlled URL path
    // The `userFilename` from the form body is appended to `uploadDir` and converted
    // directly to a `URL(fileURLWithPath:)` without canonicalization or prefix check.
    func uploadDocument(req: Request) async throws -> Response {
        struct DocPayload: Content {
            var content: String
            var userFilename: String  // e.g., supplied by client
        }
        let payload = try req.content.decode(DocPayload.self)
        let fileData = Data(payload.content.utf8)

        // Attacker supplies userFilename: ../../../private/etc/sudoers
        let fileURL = URL(fileURLWithPath: uploadDir + payload.userFilename)
        try fileData.write(to: fileURL, options: .atomic)

        return Response(status: .created, body: .init(string: "Document saved at \(fileURL.path)"))
    }
}
