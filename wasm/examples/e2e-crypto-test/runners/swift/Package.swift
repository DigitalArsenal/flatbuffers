// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "E2ECryptoTest",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        // Use the local FlatBuffers library from the parent flatbuffers repository
        .package(path: "../../../../.."),
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
            dependencies: [
                "CWasmtime",
                .product(name: "FlatBuffers", package: "flatbuffers"),
            ],
            path: ".",
            sources: ["TestRunner.swift", "message_generated.swift"],
            cSettings: [
                .unsafeFlags(["-I", "wasmtime-c-api/include"]),
            ],
            swiftSettings: [
                .unsafeFlags(["-I", "wasmtime-c-api/include"]),
            ],
            linkerSettings: [
                .unsafeFlags(["-L", "wasmtime-c-api/lib"]),
                .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../../../wasmtime-c-api/lib"]),
                .linkedLibrary("wasmtime"),
            ]
        ),
    ]
)
