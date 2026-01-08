// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "E2ECryptoTest",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        .package(url: "https://github.com/swiftwasm/WasmKit.git", from: "0.1.0"),
    ],
    targets: [
        .executableTarget(
            name: "E2ECryptoTest",
            dependencies: [
                .product(name: "WasmKit", package: "WasmKit"),
                .product(name: "WASI", package: "WasmKit"),
            ],
            path: ".",
            sources: ["TestRunner.swift"]
        ),
    ]
)
