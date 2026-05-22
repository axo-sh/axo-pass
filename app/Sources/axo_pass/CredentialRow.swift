import CryptoKit
import SwiftUI
import AxoPassFFI

struct CredentialRow: View {
  let cred: CredentialInfo
  let secret: SymmetricKey?
  let error: String?
  let isRevealing: Bool
  let onReveal: () -> Void
  let onHide: () -> Void
  let onCopy: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      LabeledContent {
        actionButtons
      } label: {
        VStack(alignment: .leading, spacing: 2) {
          Text(cred.title)
          Text(cred.key).font(.caption).foregroundStyle(.secondary)
        }
      }

      if let err = error {
        Text(err).font(.caption).foregroundStyle(.red)
      }

      if let secret {
        LabeledContent("Value") {
          SecretValueView(secret: secret)
        }
      }
    }
    .padding(.vertical, 4)
  }

  @ViewBuilder
  private var actionButtons: some View {
    if isRevealing {
      ProgressView().controlSize(.small)
    } else if secret != nil {
      HStack(spacing: 4) {
        Button("Copy", action: onCopy).buttonStyle(.bordered).controlSize(.small)
        Button("Hide", action: onHide).buttonStyle(.bordered).controlSize(.small)
      }
    } else {
      Button("Reveal", action: onReveal).buttonStyle(.bordered).controlSize(.small)
    }
  }
}

private struct SecretValueView: View {
  let secret: SymmetricKey

  var body: some View {
    let value = secret.withUnsafeBytes { ptr in
      String(bytes: ptr, encoding: .utf8) ?? "(binary data)"
    }
    Text(value)
      .font(.system(.body, design: .monospaced))
      .textSelection(.enabled)
      .padding(6)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
  }
}
