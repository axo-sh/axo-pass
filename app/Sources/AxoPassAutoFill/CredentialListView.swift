import AuthenticationServices
import AxoArtwork
import SwiftUI

/// What the extension shows inside the AutoFill popover.
struct CredentialListView: View {
  @Bindable var model: CredentialListModel
  @State private var filter = ""
  @State private var showAll = false

  /// Other logins are listed after the user asks, or while filtering.
  private var showsOthers: Bool {
    showAll || !filter.trimmingCharacters(in: .whitespaces).isEmpty
  }

  var body: some View {
    VStack(spacing: 0) {
      header
      Divider()
      content
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    .frame(minWidth: 340, minHeight: 380)
  }

  private var header: some View {
    HStack(spacing: 8) {
      AxoStaticLogo()
        .frame(width: 28, height: 28)
      VStack(alignment: .leading, spacing: 1) {
        Text("Axo Pass")
          .font(.headline)
        if let host = model.host {
          Text(host)
            .font(.caption)
            .foregroundStyle(.secondary)
        }
      }
      Spacer()
      Button("Cancel") { model.onCancel?() }
        .keyboardShortcut(.cancelAction)
    }
    .padding(12)
  }

  @ViewBuilder
  private var content: some View {
    switch model.state {
    case .loading:
      message(
        icon: "touchid", title: "Waiting for Axo Pass",
        detail: "Confirm the request in the Axo Pass window to unlock your vaults.",
        showsProgress: true)

    case .filling(let account):
      message(
        icon: "touchid", title: "Filling \(account)",
        detail: "Confirm the request in the Axo Pass window.", showsProgress: true)

    case .list(let items):
      list(items)

    case .passkeys(let accounts):
      passkeyList(accounts)

    case .appUnavailable:
      message(
        icon: "bolt.horizontal.circle", title: "Axo Pass is not running",
        detail: "Open Axo Pass, then try again.",
        action: ("Open Axo Pass", { model.onOpenApp?() }))

    case .failed(let detail):
      message(
        icon: "exclamationmark.triangle", title: "Could not reach your vaults",
        detail: detail, action: ("Try Again", { model.retry() }))

    case .configuration(let onDone):
      configuration(onDone: onDone)
    }
  }

  private func list(_ logins: LoginList) -> some View {
    let matches = filtered(logins.matches)
    let others = filtered(logins.others)
    let site = model.host ?? "this site"
    let noun = model.purpose == .oneTimeCode ? "one-time codes" : "logins"
    return VStack(spacing: 0) {
      if logins.matches.isEmpty && logins.others.isEmpty {
        message(
          icon: "key.slash", title: "No matching \(noun)",
          detail: model.host.map { "Nothing in your vaults matches \($0)." }
            ?? "AutoFill did not say which site this is for.")
      } else {
        List {
          Section {
            if logins.matches.isEmpty {
              Text("No \(noun) saved for \(site).")
                .font(.callout)
                .foregroundStyle(.white)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity, minHeight: 56)
                .padding(8)
                .background(.white.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                .overlay(
                  RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(.white.opacity(0.3), lineWidth: 1)
                )
                .listRowSeparator(.hidden)
            }
            ForEach(matches) { item in loginButton(item) }
          }
          if !logins.others.isEmpty {
            if showsOthers {
              Section {
                Divider()
                  .listRowSeparator(.hidden)
                ForEach(others) { item in loginButton(item) }
              }
            } else {
              Section {
                Button("Show all logins") { showAll = true }
                  .buttonStyle(.link)
                  .frame(maxWidth: .infinity)
                  .listRowSeparator(.hidden)
              }
            }
          }
        }
        .listStyle(.plain)
        .searchable(text: $filter, prompt: "Filter")
      }
    }
  }

  /// Passkey account cards. Matches the account list of the app's sign-in prompt.
  private func passkeyList(_ accounts: [PasskeyAccount]) -> some View {
    ScrollView {
      VStack(spacing: 14) {
        Text("Choose an account for **\(model.host ?? "this site")**")
          .font(.title3)
          .multilineTextAlignment(.center)
        VStack(spacing: 8) {
          ForEach(accounts) { account in
            Button {
              model.onSelectPasskey?(account)
            } label: {
              passkeyCard(account)
            }
            .buttonStyle(.plain)
          }
        }
      }
      .padding(24)
    }
  }

  private func passkeyCard(_ account: PasskeyAccount) -> some View {
    HStack(spacing: 10) {
      Image(systemName: "person.badge.key.fill")
        .font(.body)
        .foregroundStyle(.secondary)
        .frame(width: 20)
      Text(account.userName)
        .font(.body.weight(.medium))
      Spacer()
    }
    .padding(12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(
      RoundedRectangle(cornerRadius: 10, style: .continuous)
        .fill(.quaternary.opacity(0.5))
    )
    .contentShape(Rectangle())
  }

  private func loginButton(_ item: Login) -> some View {
    Button {
      model.onSelect?(item)
    } label: {
      row(item)
    }
    .buttonStyle(.plain)
    .listRowSeparator(.hidden)
  }

  private func row(_ item: Login) -> some View {
    HStack(spacing: 10) {
      avatar(item)
      VStack(alignment: .leading, spacing: 1) {
        Text(item.title)
          .fontWeight(.medium)
          .lineLimit(1)
        Text([item.accountName, item.vaultName].compactMap { $0 }.joined(separator: " · "))
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(.vertical, 3)
    .contentShape(Rectangle())
    .help(item.reason)
  }

  /// Rounded square with the first letter of the title. Color is derived from the title.
  private func avatar(_ item: Login) -> some View {
    let seed = item.title.lowercased().unicodeScalars.reduce(5381) { ($0 &* 33) &+ Int($1.value) }
    let hue = Double(abs(seed) % 360) / 360
    let letter = item.title.first.map { String($0).uppercased() } ?? "?"
    return Text(letter)
      .font(.system(size: 13, weight: .semibold))
      .foregroundStyle(.white)
      .frame(width: 28, height: 28)
      .background(
        Color(hue: hue, saturation: 0.6, brightness: 0.7),
        in: RoundedRectangle(cornerRadius: 6, style: .continuous))
  }

  private func filtered(_ items: [Login]) -> [Login] {
    let needle = filter.trimmingCharacters(in: .whitespaces).lowercased()
    guard !needle.isEmpty else { return items }
    return items.filter {
      $0.title.lowercased().contains(needle)
        || $0.accountName.lowercased().contains(needle)
        || ($0.matched?.host.lowercased().contains(needle) ?? false)
    }
  }

  private func configuration(onDone: @escaping () -> Void) -> some View {
    VStack(spacing: 12) {
      Image(systemName: "checkmark.circle")
        .font(.system(size: 36))
        .foregroundStyle(.tint)
      Text("Axo Pass is ready to fill passwords")
        .font(.headline)
      Text("Your vaults stay locked. Axo Pass asks you to confirm each fill.")
        .font(.subheadline)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
      Button("Done", action: onDone)
        .keyboardShortcut(.defaultAction)
    }
    .padding(24)
  }

  private func message(
    icon: String, title: String, detail: String, showsProgress: Bool = false,
    action: (String, () -> Void)? = nil
  ) -> some View {
    VStack(spacing: 10) {
      if showsProgress {
        ProgressView()
          .controlSize(.small)
      } else {
        Image(systemName: icon)
          .font(.system(size: 30))
          .foregroundStyle(.secondary)
      }
      Text(title)
        .font(.headline)
      Text(detail)
        .font(.subheadline)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
      if let action {
        Button(action.0, action: action.1)
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}
