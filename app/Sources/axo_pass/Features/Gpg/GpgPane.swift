import AppKit
import AxoPassFFI
import SwiftUI

struct GpgPane: View {
  @Bindable var model: GpgModel
  @Environment(\.openSettings) private var openSettings

  var body: some View {
    List(selection: $model.selectedFingerprint) {
      if let err = model.loadError {
        Label(err, systemImage: "exclamationmark.triangle")
          .font(.caption)
          .foregroundStyle(.red)
      } else if model.keys.isEmpty {
        Text("No GPG keys found").foregroundStyle(.secondary)
      } else {
        // Secret keys lead the list without a header of their own: they are
        // the usual case, and the "Public Only" header below says what the
        // split is.
        ForEach(model.secretKeys) { key in
          GpgKeyRow(key: key)
        }
        if !model.publicOnlyKeys.isEmpty {
          Section("Public Only") {
            ForEach(model.publicOnlyKeys) { key in
              GpgKeyRow(key: key)
            }
          }
        }
      }
      if !model.orphanedPasswords.isEmpty {
        Section("Other Saved Passphrases") {
          ForEach(model.orphanedPasswords, id: \.keyId) { entry in
            VStack(alignment: .leading, spacing: 2) {
              Text(entry.keyId)
                .font(.system(.caption, design: .monospaced))
                .lineLimit(1)
                .truncationMode(.middle)
              Text("No matching key in the keyring")
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
            .contextMenu {
              Button("Delete", role: .destructive) {
                Task { await model.delete(entry) }
              }
            }
          }
        }
      }
    }
    .safeAreaInset(edge: .bottom) { agentSummaryBar }
    .paneBackground()
    .navigationTitle("GPG")
    .navigationSplitViewColumnWidth(min: 200, ideal: 260)
    .toolbar {
      ToolbarItem {
        Button {
          Task { await model.reload() }
        } label: {
          Label("Reload", systemImage: "arrow.clockwise")
        }
      }
    }
    .task { await model.reload() }
    // The file may be edited outside the app, so re-read it on reactivation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.refreshConfStatus()
    }
  }

  /// Compact pinentry state at the foot of the list, opening the Settings tab
  /// that configures it.
  private var agentSummaryBar: some View {
    Button {
      NSApp.activate(ignoringOtherApps: true)
      openSettings()
    } label: {
      HStack(spacing: 6) {
        Circle()
          .fill(GpgPinentryStyle.color(model.confStatus?.state))
          .frame(width: 7, height: 7)
        Text(summary)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
        Spacer()
        Image(systemName: "chevron.right")
          .font(.caption2)
          .foregroundStyle(.tertiary)
      }
      .contentShape(Rectangle())
      .padding(.horizontal, 12)
      .padding(.vertical, 8)
    }
    .buttonStyle(.plain)
    .background(.bar)
    .overlay(alignment: .top) { Divider() }
    .help("Configure passphrase prompts")
  }

  private var summary: String {
    "Prompts \(GpgPinentryStyle.label(model.confStatus?.state).lowercased())"
  }
}

/// Shared presentation for `GpgPinentryState`. A nil state means the conf file
/// has not been checked yet.
enum GpgPinentryStyle {
  static func label(_ state: GpgPinentryState?) -> String {
    switch state {
    case .configured: return "Configured"
    case .notConfigured: return "Not Configured"
    case .otherProgram: return "Other Pinentry"
    case nil: return "Unknown"
    }
  }

  static func icon(_ state: GpgPinentryState?) -> String {
    switch state {
    case .configured: return "checkmark.circle.fill"
    case .notConfigured: return "circle"
    case .otherProgram: return "exclamationmark.triangle.fill"
    case nil: return "questionmark.circle"
    }
  }

  static func color(_ state: GpgPinentryState?) -> Color {
    switch state {
    case .configured: return .green
    case .notConfigured: return .secondary
    case .otherProgram: return .orange
    case nil: return .secondary
    }
  }
}

extension GpgKeyEntry: Identifiable {
  public var id: String { fingerprint }

  /// Short form of the key id, as gpg prints it with `--keyid-format short`.
  var shortKeyId: String { String(keyId.suffix(8)) }

  /// `RSA 4096`, or `ed25519` for a curve key whose size says little.
  var algorithmLabel: String { GpgFormat.algorithm(algorithm, keyLength: keyLength, curve: curve) }

  var isUsable: Bool { !isExpired && !isRevoked && !isDisabled }

  /// One entry per keygrip on this key that needs a passphrase and has its
  /// secret half on this machine, saying whether that passphrase is saved.
  /// Each is saved on its own, so a key can be partly saved.
  var passphraseSlots: [Bool] {
    var slots: [Bool] = []
    if secretState == .present && requiresPassphrase {
      slots.append(hasSavedPassword)
    }
    for subkey in subkeys where subkey.secretState == .present && subkey.requiresPassphrase {
      slots.append(subkey.hasSavedPassword)
    }
    return slots
  }
}

extension GpgSubkeyEntry: Identifiable {
  public var id: String { keyId }

  var algorithmLabel: String { GpgFormat.algorithm(algorithm, keyLength: keyLength, curve: curve) }
}

enum GpgFormat {
  /// Curve keys are named by their curve, which says more than the bit length.
  static func algorithm(_ algorithm: String, keyLength: UInt32, curve: String?) -> String {
    if let curve, !curve.isEmpty { return curve }
    if keyLength > 0 { return "\(algorithm) \(keyLength)" }
    return algorithm
  }

  static func capabilityList(_ capabilities: [GpgCapability]) -> String {
    capabilities.map(label).joined(separator: " · ")
  }

  static func label(_ capability: GpgCapability) -> String {
    switch capability {
    case .sign: return "Sign"
    case .certify: return "Certify"
    case .encrypt: return "Encrypt"
    case .authenticate: return "Authenticate"
    }
  }

  static func label(_ trust: GpgTrust) -> String {
    switch trust {
    case .unknown: return "Unknown trust"
    case .undefined: return "Undefined trust"
    case .never: return "Never trust"
    case .marginal: return "Marginal trust"
    case .full: return "Full trust"
    case .ultimate: return "Ultimate trust"
    case .expired: return "Expired"
    case .revoked: return "Revoked"
    case .invalid: return "Invalid"
    case .disabled: return "Disabled"
    }
  }

  static func label(_ state: GpgSecretState) -> String {
    switch state {
    case .none: return "Public only"
    case .present: return "Secret key"
    case .card: return "Smartcard"
    case .offline: return "Offline stub"
    }
  }

  /// A fingerprint in gpg's grouped form: blocks of four hex digits.
  static func groupedFingerprint(_ fingerprint: String) -> String {
    let blocks = stride(from: 0, to: fingerprint.count, by: 4).map { offset -> String in
      let start = fingerprint.index(fingerprint.startIndex, offsetBy: offset)
      let end = fingerprint.index(start, offsetBy: 4, limitedBy: fingerprint.endIndex)
      return String(fingerprint[start..<(end ?? fingerprint.endIndex)])
    }
    return blocks.joined(separator: " ")
  }

  /// Key ids are shown the way gpg prints them, with an `0x` prefix.
  static func keyIdLabel(_ keyId: String) -> String { "0x\(keyId)" }

  static func date(_ unixSeconds: Int64?) -> String? {
    guard let unixSeconds else { return nil }
    return dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(unixSeconds)))
  }

  private static let dateFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateStyle = .long
    formatter.timeStyle = .none
    return formatter
  }()
}

private struct GpgKeyRow: View {
  let key: GpgKeyEntry

  var body: some View {
    VStack(alignment: .leading, spacing: 2) {
      HStack(spacing: 4) {
        Text(key.name).fontWeight(.semibold).lineLimit(1)
        Spacer(minLength: 6)
        if key.isRevoked {
          KeyBadge(text: "Revoked", tint: .red)
        } else if key.isExpired {
          KeyBadge(text: "Expired", tint: .orange)
        } else if key.passphraseSlots.contains(true) {
          KeyBadge(text: "Saved", tint: .green)
        }
      }
      if let email = key.email {
        Text(email)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
      }
      Text(subtitle)
        .font(.system(.caption, design: .monospaced))
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .truncationMode(.middle)
    }
    .padding(.vertical, 3)
    .opacity(key.isUsable ? 1 : 0.6)
  }

  private var subtitle: String {
    "\(key.shortKeyId) · \(key.algorithmLabel)"
  }
}
