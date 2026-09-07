// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

// Static library + UniFFI Swift bindings are produced by `axo ffi` (see axo.toml).
// Outputs land in target/<profile>/libaxo_pass_ffi.a and Sources/{axo_pass_ffiFFI,AxoPassFFI}.

let package = Package(
    name: "Axo Pass",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(url: "git@github.com:octavore/sunshine.git", branch: "main"),
    ],
    targets: [
        .systemLibrary(
            name: "axo_pass_ffiFFI",
            path: "Sources/axo_pass_ffiFFI"
        ),
        .target(
            name: "AxoPassFFI",
            dependencies: ["axo_pass_ffiFFI"],
            path: "Sources/AxoPassFFI",
            // uniffi-bindgen's output for foreign-implemented callback
            // interfaces keeps a static vtable pointer, which Swift 6 rejects
            // as a non-Sendable global. It is generated code, so build it in
            // Swift 5 mode rather than patching it after every codegen run.
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "axo_pass",
            dependencies: [
                "AxoPassFFI",
                .product(name: "Sunshine", package: "sunshine"),
            ],
            path: "Sources/axo_pass",
            linkerSettings: [
                // target/swift-lib is a symlink maintained by scripts/build-ffi.sh
                // pointing at target/debug or target/release depending on PROFILE.
                .unsafeFlags(["-L../target/swift-lib"]),
                .linkedLibrary("axo_pass_ffi"),
                .linkedFramework("AppKit"),
                .linkedFramework("Foundation"),
                .linkedFramework("CoreFoundation"),
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("LocalAuthenticationEmbeddedUI"),
            ]
        ),
    ]
)
