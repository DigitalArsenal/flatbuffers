// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "FlatBuffersEncryption",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "FlatBuffersEncryption",
            targets: ["FlatBuffersEncryption"]),
        .executable(
            name: "encryption-demo",
            targets: ["EncryptionDemo"]),
    ],
    dependencies: [
        // WasmKit - Pure Swift WebAssembly runtime
        .package(url: "https://github.com/swiftwasm/WasmKit.git", from: "0.1.0"),
    ],
    targets: [
        .target(
            name: "FlatBuffersEncryption",
            dependencies: [
                .product(name: "WasmKit", package: "WasmKit"),
                .product(name: "WASI", package: "WasmKit"),
            ]),
        .executableTarget(
            name: "EncryptionDemo",
            dependencies: ["FlatBuffersEncryption"]),
        .testTarget(
            name: "FlatBuffersEncryptionTests",
            dependencies: ["FlatBuffersEncryption"]),
    ]
)
