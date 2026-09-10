import Foundation

// An app extension is launched by the system through NSExtensionMain, which
// reads NSExtensionPrincipalClass out of the bundle's Info.plist and hosts that
// class. Xcode gets this by linking with `-e _NSExtensionMain`; an SPM
// executable target has to call it from its own entry point instead.
@_silgen_name("NSExtensionMain")
func NSExtensionMain() -> Int32

exit(NSExtensionMain())
