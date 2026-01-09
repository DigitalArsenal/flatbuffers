// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "E2ECryptoTest",
    platforms: [
        .macOS(.v13)
    ],
    targets: [
        // System library for Wasmtime C API
        .systemLibrary(
            name: "CWasmtime",
            path: "CWasmtime",
            pkgConfig: nil,
            providers: []
        ),
        .executableTarget(
            name: "E2ECryptoTest",
            dependencies: ["CWasmtime"],
            path: ".",
            sources: ["TestRunner.swift"],
            cSettings: [
                .unsafeFlags(["-I", "wasmtime-c-api/include"]),
            ],
            swiftSettings: [
                .unsafeFlags(["-I", "wasmtime-c-api/include"]),
            ],
            linkerSettings: [
                .unsafeFlags(["-L", "wasmtime-c-api/lib"]),
                .linkedLibrary("wasmtime"),
            ]
        ),
    ]
)
