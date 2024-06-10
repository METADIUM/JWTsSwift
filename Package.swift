// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JWTsSwift",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "JWTsSwift",
            targets: ["JWTsSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Boilertalk/secp256k1.swift", .upToNextMajor(from: "0.1.7"))
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "JWTsSwift",
            dependencies: [
                .product(name: "secp256k1", package: "secp256k1.swift")
            ]),

        .testTarget(
            name: "JWTsSwiftTests",
            dependencies: ["JWTsSwift"]),
    ]
)
