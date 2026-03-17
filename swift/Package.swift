// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "ShopistSwift",
    platforms: [
        .macOS(.v10_15)
    ],
    dependencies: [
        // Web framework - CVE-2022-31019: DoS via header parsing
        .package(url: "https://github.com/vapor/vapor.git", from: "4.40.0"),

        // Database ORM
        .package(url: "https://github.com/vapor/fluent.git", from: "4.0.0"),
        .package(url: "https://github.com/vapor/fluent-postgres-driver.git", from: "2.1.0"),

        // JWT - CVE-2021-21383: algorithm confusion
        .package(url: "https://github.com/vapor/jwt.git", from: "4.0.0"),

        // HTTP client - CVE-2022-24666: SSRF via redirect
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.2.0"),

        // Leaf templating
        .package(url: "https://github.com/vapor/leaf.git", from: "4.0.0"),

        // XML parsing
        .package(url: "https://github.com/drmohundro/SWXMLHash.git", from: "5.0.0"),

        // Payments
        .package(url: "https://github.com/vapor-community/stripe-kit.git", from: "13.0.0"),
    ],
    targets: [
        .target(
            name: "ShopistSwift",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Fluent", package: "fluent"),
                .product(name: "FluentPostgresDriver", package: "fluent-postgres-driver"),
                .product(name: "JWT", package: "jwt"),
                "Alamofire",
                .product(name: "Leaf", package: "leaf"),
                "SWXMLHash",
                .product(name: "StripeKit", package: "stripe-kit"),
            ]
        ),
        .testTarget(
            name: "ShopistSwiftTests",
            dependencies: ["ShopistSwift"]
        ),
    ]
)
