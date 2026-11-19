import AppKit
import SwiftUI

/// Settings for a generated password.
struct PasswordGeneratorOptions: Equatable {
  var length: Int = 20
  var lowercase = true
  var uppercase = true
  var digits = true
  var symbols = true
  /// Leave out look-alike characters such as `0`, `O`, `1`, `l`, and `I`.
  var avoidAmbiguous = false

  static let lengthRange = 8...64

  private static let ambiguous = Set("0O1lI|")

  /// Character sets in use, one per enabled class.
  var pools: [[Character]] {
    var sets: [String] = []
    if lowercase { sets.append("abcdefghijklmnopqrstuvwxyz") }
    if uppercase { sets.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ") }
    if digits { sets.append("0123456789") }
    if symbols { sets.append("!@#$%^&*-_=+") }
    return sets.map { set in
      Array(set).filter { !(avoidAmbiguous && Self.ambiguous.contains($0)) }
    }
  }

  var isValid: Bool { !pools.isEmpty }
}

enum PasswordGenerator {
  /// A random password with at least one character from each enabled class.
  /// Returns an empty string if no class is enabled.
  static func generate(_ options: PasswordGeneratorOptions) -> String {
    let pools = options.pools
    guard !pools.isEmpty else { return "" }
    let all = pools.flatMap { $0 }
    let length = max(options.length, pools.count)
    var rng = SystemRandomNumberGenerator()
    var chars = pools.map { $0.randomElement(using: &rng)! }
    while chars.count < length {
      chars.append(all.randomElement(using: &rng)!)
    }
    chars.shuffle(using: &rng)
    return String(chars)
  }
}

/// Controls and preview for generating a password. `onUse` adds a button that
/// hands the password to the caller.
struct PasswordGeneratorView: View {
  var onUse: ((String) -> Void)?

  @State private var options = PasswordGeneratorOptions()
  @State private var password = ""
  @State private var justCopied = false

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack(alignment: .center, spacing: 8) {
        Text(password)
          .font(.system(.body, design: .monospaced))
          .textSelection(.enabled)
          .lineLimit(4)
          .fixedSize(horizontal: false, vertical: true)
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(.vertical, 6)
          .padding(.horizontal, 8)
          .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        Button {
          regenerate()
        } label: {
          Label("Regenerate", systemImage: "arrow.clockwise")
            .labelStyle(.iconOnly)
        }
        .help("Generate a new password")
        .disabled(!options.isValid)
      }

      HStack {
        Text("Length")
        Slider(
          value: Binding(
            get: { Double(options.length) },
            set: { options.length = Int($0.rounded()) }),
          in: Double(
            PasswordGeneratorOptions.lengthRange.lowerBound)...Double(
              PasswordGeneratorOptions.lengthRange.upperBound))
        Text("\(options.length)")
          .monospacedDigit()
          .frame(width: 24, alignment: .trailing)
      }

      Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
        GridRow {
          Toggle("Lowercase", isOn: $options.lowercase)
          Toggle("Uppercase", isOn: $options.uppercase)
        }
        GridRow {
          Toggle("Digits", isOn: $options.digits)
          Toggle("Symbols", isOn: $options.symbols)
        }
      }
      Toggle("Avoid ambiguous characters", isOn: $options.avoidAmbiguous)

      HStack {
        Spacer()
        Button(justCopied ? "Copied" : "Copy") { copy() }
          .disabled(password.isEmpty)
        if let onUse {
          Button("Use Password") { onUse(password) }
            .keyboardShortcut(.defaultAction)
            .disabled(password.isEmpty)
        }
      }
    }
    .toggleStyle(.checkbox)
    // Reset the font, which a hosting editor may have set to monospaced.
    .font(.body)
    .padding(16)
    .onAppear { regenerate() }
    .onChange(of: options) { _, _ in regenerate() }
  }

  private func regenerate() {
    password = PasswordGenerator.generate(options)
    justCopied = false
  }

  private func copy() {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(password, forType: .string)
    justCopied = true
  }
}
