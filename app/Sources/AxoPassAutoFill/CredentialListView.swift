import AuthenticationServices
import SwiftUI

/// What the extension shows inside the AutoFill popover.
struct CredentialListView: View {
  @Bindable var model: CredentialListModel
  @State private var filter = ""

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
      Image(systemName: "lock.shield")
        .foregroundStyle(.tint)
      VStack(alignment: .leading, spacing: 1) {
        Text("Axo Pass")
          .font(.headline)
        if let service = model.service, !service.isEmpty {
          Text(service)
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

    case let .filling(account):
      message(
        icon: "touchid", title: "Filling \(account)",
        detail: "Confirm the request in the Axo Pass window.", showsProgress: true)

    case let .list(items):
      list(items)

    case .appUnavailable:
      message(
        icon: "bolt.horizontal.circle", title: "Axo Pass is not running",
        detail: "Open Axo Pass, then try again.",
        action: ("Open Axo Pass", { model.onOpenApp?() }))

    case let .failed(detail):
      message(
        icon: "exclamationmark.triangle", title: "Could not reach your vaults",
        detail: detail, action: ("Try Again", { model.retry() }))

    case let .configuration(onDone):
      configuration(onDone: onDone)
    }
  }

  private func list(_ items: [AutofillItem]) -> some View {
    let matches = filtered(items)
    return VStack(spacing: 0) {
      if items.isEmpty {
        message(
          icon: "key.slash", title: "No matching logins",
          detail: model.service.map { "Nothing in your vaults matches \($0)." }
            ?? "No item in your vaults has a password to fill.")
      } else {
        List(matches) { item in
          Button {
            model.onSelect?(item)
          } label: {
            row(item)
          }
          .buttonStyle(.plain)
        }
        .listStyle(.inset)
        .searchable(text: $filter, prompt: "Filter")
      }
    }
  }

  private func row(_ item: AutofillItem) -> some View {
    HStack(spacing: 10) {
      VStack(alignment: .leading, spacing: 2) {
        Text(item.title)
          .fontWeight(.medium)
        Text(item.accountName)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer()
      Text(item.vaultKey)
        .font(.caption2)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(.quaternary, in: Capsule())
    }
    .padding(.vertical, 3)
    .contentShape(Rectangle())
  }

  private func filtered(_ items: [AutofillItem]) -> [AutofillItem] {
    let needle = filter.trimmingCharacters(in: .whitespaces).lowercased()
    guard !needle.isEmpty else { return items }
    return items.filter {
      $0.title.lowercased().contains(needle)
        || $0.accountName.lowercased().contains(needle)
        || $0.urls.contains { $0.lowercased().contains(needle) }
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
