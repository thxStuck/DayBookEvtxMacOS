// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "DaybookKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "EvtxCore", targets: ["EvtxCore"]),
        .library(name: "DaybookStore", targets: ["DaybookStore"]),
        .library(name: "DaybookSigma", targets: ["DaybookSigma"]),
        .executable(name: "evtxdump", targets: ["evtxdump"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jpsim/Yams.git", exact: "6.2.2"),
    ],
    targets: [
        .target(name: "EvtxCore"),
        .target(name: "DaybookStore", dependencies: ["EvtxCore"]),
        .target(name: "DaybookSigma", dependencies: ["EvtxCore", "DaybookStore", .product(name: "Yams", package: "Yams")]),
        .executableTarget(name: "evtxdump", dependencies: ["EvtxCore", "DaybookStore", "DaybookSigma"]),
    ]
)
