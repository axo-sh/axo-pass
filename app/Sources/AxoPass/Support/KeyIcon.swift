/// SF Symbols for key sources and vaults. Every surface takes its symbol from here.
enum KeyIcon {
  case ssh
  case gpg
  case age
  case vault

  /// Outline symbol for lists, empty states, and the palette.
  var symbol: String {
    switch self {
    case .ssh: return "key.horizontal"
    case .gpg: return "signature"
    case .age: return "lock.rectangle.stack"
    case .vault: return "archivebox"
    }
  }

  /// Filled symbol for detail headers and sheets. The signature symbol has no filled variant.
  var filledSymbol: String {
    switch self {
    case .gpg: return symbol
    default: return symbol + ".fill"
    }
  }
}
