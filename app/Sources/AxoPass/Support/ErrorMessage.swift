import AxoPassFFI
import Foundation

extension FfiError {
  /// Message for the user, without the case name wrapped around it.
  var userMessage: String {
    switch self {
    case .AuthCancelled: "Authentication cancelled"
    case .AuthExpired: "Authentication expired"
    case .NotFound(let message): "Not found: \(message)"
    case .FilePending: "File contents are downloading"
    case .FileMissing: "File contents are not on this Mac"
    case .FileBlobMismatch: "File contents are damaged"
    case .SshKeyPassphraseRequired: "The SSH key is encrypted and needs a passphrase"
    case .SshKeyWrongPassphrase: "The passphrase does not decrypt the SSH key"
    case .SshKeyDuplicate(let fingerprint): "This vault already holds the SSH key \(fingerprint)"
    case .InvalidInput(let message), .Internal(let message): message
    case .Poisoned: "State corrupted (mutex poisoned)"
    }
  }
}

extension Error {
  /// Message for the user. Core errors read as their message only.
  var userMessage: String {
    if let error = self as? FfiError {
      return error.userMessage
    }
    return String(describing: self)
  }
}
