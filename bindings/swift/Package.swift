// swift-tools-version:5.9
// The Swift binding of the Snailfish sync engine. Run `make bindings-swift`
// first: it writes Sources/Snailfish/Snailfish.swift and
// build/Snailfish.xcframework.
import PackageDescription

let package = Package(
    name: "Snailfish",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "Snailfish", targets: ["Snailfish"])],
    targets: [
        .binaryTarget(name: "snailfishFFI", path: "build/Snailfish.xcframework"),
        .target(name: "Snailfish", dependencies: ["snailfishFFI"]),
        .testTarget(
            name: "SnailfishTests",
            dependencies: ["Snailfish"],
            resources: [.copy("vectors")]
        ),
    ]
)
