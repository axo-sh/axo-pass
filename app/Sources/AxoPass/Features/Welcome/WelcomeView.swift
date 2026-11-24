import AppKit
import SwiftUI

/// Window of the first run. Offers three ways to get a first vault: a new
/// vault, an import from 1Password, or a setup from another Mac. If a vault
/// already exists, a Skip button goes straight to the integrations page.
///
/// Shown in place of the main window while no vault exists and
/// `hasCompletedFirstRun` is unset. The app is locked until a choice is made.
/// The choice raises the unlock prompt first, since the pairing and kit
/// sheets and the vault write need an unlocked app. After a choice finishes,
/// the window sets `hasCompletedFirstRun`, closes, and asks for the main
/// window, which opens unlocked. Closing the window without a choice leaves
/// `hasCompletedFirstRun` unset, so the next launch shows it again.
struct WelcomeView: View {
  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  @Environment(WindowRequests.self) private var windows
  @Environment(\.dismissWindow) private var dismissWindow

  private enum Choice {
    case startFresh
    case importItems
    case pair
    case kitImport
  }

  @State private var working: Choice? = nil
  @State private var error: String? = nil
  /// Whether the pairing and kit choices are showing.
  @State private var showingSyncChoices = false
  /// Whether a sync sheet opened by a choice is showing. Closing it ends the
  /// choice.
  @State private var syncChoiceOpen = false
  /// Whether the import flow is showing in place of the choices. Finishing it
  /// ends the choice.
  @State private var showingItemImport = false
  /// Whether the integrations page is showing. A choice that brought in a
  /// vault ends here, and its Done button ends the first run.
  @State private var showingIntegrations = false
  @State private var sshModel = SshModel()
  @State private var shellModel = ShellIntegrationModel()

  private let width: CGFloat = 460

  /// Reason shown with the unlock prompt. Without Touch ID the prompt asks for
  /// the login password.
  private var unlockReason: String {
    model.biometry == .touchID
      ? "Axo Pass uses Touch ID to protect your vaults."
      : "Axo Pass uses your login password to protect your vaults."
  }

  /// Choices page and import flow side by side. The import flow slides in from
  /// the right and the choices page moves out to the left. The window keeps
  /// the height of the taller page.
  var body: some View {
    ZStack(alignment: .top) {
      choicesPage
        .offset(x: showingItemImport || showingIntegrations ? -width : 0)
        .allowsHitTesting(!showingItemImport && !showingIntegrations)
        .accessibilityHidden(showingItemImport || showingIntegrations)

      if showingItemImport {
        ItemImportSheet(
          model: model,
          onFinished: { _ in showIntegrations() },
          onCancel: { setShowingItemImport(false) }
        )
        .transition(.move(edge: .trailing))
        .offset(x: showingIntegrations ? -width : 0)
        .allowsHitTesting(!showingIntegrations)
      }

      if showingIntegrations {
        WelcomeIntegrationsPage(ssh: sshModel, shell: shellModel, onDone: finish)
          .transition(.move(edge: .trailing))
      }
    }
    .frame(width: width)
    .clipped()
    .syncSheets()
    .onChange(of: sync.sheet?.id) { old, new in
      guard old != nil, new == nil, syncChoiceOpen else { return }
      syncChoiceOpen = false
      endSyncChoice()
    }
  }

  private var choicesPage: some View {
    VStack(spacing: 20) {
      AxoLogo(spins: false)
        .frame(width: 72, height: 72)

      VStack(spacing: 6) {
        Text("Welcome to Axo Pass")
          .font(.title)
          .fontWeight(.semibold)
        Text(
          "Axo Pass keeps your logins, SSH keys, and GPG keys in vaults on this Mac. Choose how to set up your first vault."
        )
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .lineSpacing(4)
        .fixedSize(horizontal: false, vertical: true)
      }

      VStack(spacing: 10) {
        Button {
          choose(.startFresh)
        } label: {
          ChoiceLabel(
            title: "Set up a new vault",
            detail: "You may import passwords or enable sync later.",
            symbol: "plus.circle.fill")
        }
        .buttonStyle(.plain)

        Button {
          choose(.importItems)
        } label: {
          ChoiceLabel(
            title: "Import passwords",
            detail: "Bring in logins from a 1Password or Apple Passwords export.",
            symbol: "square.and.arrow.down.fill")
        }
        .buttonStyle(.plain)

        Button {
          showingSyncChoices = true
        } label: {
          ChoiceLabel(
            title: "Set up from another device",
            detail: "Add vaults that sync from a device that has them.",
            symbol: "laptopcomputer.and.arrow.down")
        }
        .buttonStyle(.plain)
        .popover(isPresented: $showingSyncChoices, arrowEdge: .trailing) {
          VStack(alignment: .leading, spacing: 8) {
            Button("Pair with Another Device…") {
              showingSyncChoices = false
              choose(.pair)
            }
            Button("Use a Recovery Kit…") {
              showingSyncChoices = false
              choose(.kitImport)
            }
          }
          .buttonStyle(.link)
          .padding(14)
        }
      }
      .disabled(working != nil)

      VStack(spacing: 6) {
        if working != nil {
          ProgressView().controlSize(.small)
        }
        Text(unlockReason)
          .font(.callout)
          .foregroundStyle(.secondary)
        if let error = error ?? model.unlockError {
          Text(error)
            .font(.callout)
            .foregroundStyle(.red)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
      .multilineTextAlignment(.center)

      if !model.vaults.isEmpty {
        Button("Skip", action: showIntegrations)
          .buttonStyle(.link)
          .disabled(working != nil)
      }
    }
    .padding(32)
    .frame(width: width)
  }

  /// Slide the import flow in or out.
  private func setShowingItemImport(_ showing: Bool) {
    withAnimation(.smooth(duration: 0.35)) { showingItemImport = showing }
  }

  /// Run `choice`. Every choice unlocks first. A cancelled prompt leaves the
  /// window as it was.
  private func choose(_ choice: Choice) {
    guard working == nil else { return }
    working = choice
    error = nil
    Task {
      defer { working = nil }
      guard await model.unlockAndWait() else { return }
      switch choice {
      case .startFresh:
        if await model.addPersonalVault() {
          showIntegrations()
        } else {
          error = model.actionError ?? "Could not create the vault."
        }
      case .importItems:
        setShowingItemImport(true)
      case .pair:
        guard sync.ensureFolder() else { return }
        syncChoiceOpen = true
        sync.showPairing()
      case .kitImport:
        guard sync.ensureFolder() else { return }
        syncChoiceOpen = true
        sync.showKitImport()
      }
    }
  }

  /// A sync sheet closed. The choice is done if it brought in a vault, or the
  /// pairing received one. Otherwise the window stays for another choice.
  private func endSyncChoice() {
    model.reload()
    if !model.vaults.isEmpty || !sync.imports.isEmpty { showIntegrations() }
  }

  /// Slide the integrations page in. Its Done button completes the first run.
  private func showIntegrations() {
    withAnimation(.smooth(duration: 0.35)) { showingIntegrations = true }
  }

  /// Mark the first run complete, close this window, and open the main window.
  private func finish() {
    Preferences.hasCompletedFirstRun = true
    dismissWindow(id: AxoPassApp.welcomeWindowID)
    windows.requestMain()
  }
}

/// Icon, title, and one line of detail in a rounded card.
private struct ChoiceLabel: View {
  let title: String
  let detail: String
  let symbol: String

  @Environment(\.isEnabled) private var isEnabled

  var body: some View {
    HStack(spacing: 12) {
      TodayIcon(symbol: symbol, color: .accentColor)
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
          .fontWeight(.medium)
        Text(detail)
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
      }
      Spacer(minLength: 0)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    .overlay {
      RoundedRectangle(cornerRadius: 10)
        .strokeBorder(.separator)
    }
    .contentShape(.rect)
    .opacity(isEnabled ? 1 : 0.5)
  }
}
