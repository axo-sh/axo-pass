import AppKit
import SwiftUI

/// The command palette: a search field over items, keys and commands, with an
/// action list for the selected result. Keyboard navigation arrives through
/// `PaletteModel.handle`, called by the panel.
struct PaletteView: View {
  @Bindable var model: PaletteModel
  /// Where the pointer was at the last hover event that changed the selection.
  @State private var lastPointer: CGPoint?

  private static let rowHeight: CGFloat = 40
  private static let visibleRows = 8

  /// Whether the pointer has moved since the last hover selection. A row that
  /// scrolls under a still pointer, after an arrow key or a new query, also
  /// reports a hover; only real pointer movement selects.
  private func pointerMoved() -> Bool {
    let location = NSEvent.mouseLocation
    defer { lastPointer = location }
    return lastPointer != nil && lastPointer != location
  }

  var body: some View {
    VStack(spacing: 0) {
      switch model.mode {
      case .unlock:
        unlockPrompt
      case .search:
        field("Search, or vault/item/credential", text: $model.query)
        Divider()
        resultList
        Divider()
        footer
      case .actions:
        field("Filter actions", text: $model.actionQuery, prefix: model.actionTarget?.title)
        Divider()
        actionList
        Divider()
        footer
      }
    }
    .background(PaletteBackground())
    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    .overlay(
      RoundedRectangle(cornerRadius: 12, style: .continuous)
        .strokeBorder(Color.primary.opacity(0.12), lineWidth: 0.5)
    )
    .onChange(of: model.vaults.isAppUnlocked) { model.unlockedChanged() }
    .onChange(of: model.vaults.isUnlocking) { model.unlockingChanged() }
  }

  // MARK: - Search field

  private func field(_ prompt: String, text: Binding<String>, prefix: String? = nil) -> some View {
    PaletteField(prompt: prompt, text: text, prefix: prefix)
      // A new field for each mode, so focus lands in it.
      .id(model.mode)
  }

  // MARK: - Results

  private var resultList: some View {
    let results = model.results
    return Group {
      if results.isEmpty {
        Text("No results")
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity)
          .frame(height: Self.rowHeight * 2)
      } else {
        list(
          count: results.count, selection: model.selectedIndex,
          onHover: { model.selectedIndex = $0 }
        ) { index in
          let result = results[index]
          ResultRow(
            result: result, value: value(for: result), isSelected: index == model.selectedIndex
          )
          .onTapGesture {
            model.selectedIndex = index
            model.runDefault(at: index)
          }
          .task(id: result.id) { await model.loadPlainValue(for: result) }
        }
      }
    }
  }

  /// What a credential row shows for its value: the value of a plain-text
  /// credential, and a mask for a concealed one unless Option is revealing it.
  /// Nil for other rows.
  private func value(for result: PaletteResult) -> String? {
    guard let credential = result.credential else { return nil }
    if !credential.concealed { return model.plainValues[result.id] }
    if model.revealedID == result.id, let revealed = model.revealedValue { return revealed }
    return "••••••••"
  }

  private var actionList: some View {
    let actions = model.filteredActions
    return Group {
      if actions.isEmpty {
        Text("No actions")
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity)
          .frame(height: Self.rowHeight * 2)
      } else {
        list(
          count: actions.count, selection: model.selectedActionIndex,
          onHover: { model.selectedActionIndex = $0 }
        ) { index in
          ActionRow(action: actions[index], isSelected: index == model.selectedActionIndex)
            .onTapGesture {
              guard let target = model.actionTarget else { return }
              model.selectedActionIndex = index
              model.run(actions[index], of: target)
            }
        }
      }
    }
  }

  /// A scrolling list sized to its rows, up to `visibleRows`, that keeps the
  /// selected row in view. Moving the pointer over a row selects it.
  private func list<Row: View>(
    count: Int, selection: Int, onHover: @escaping (Int) -> Void,
    @ViewBuilder row: @escaping (Int) -> Row
  ) -> some View {
    ScrollViewReader { proxy in
      ScrollView {
        LazyVStack(spacing: 0) {
          ForEach(0..<count, id: \.self) { index in
            row(index)
              .frame(height: Self.rowHeight)
              .id(index)
              .onContinuousHover { phase in
                guard case .active = phase, pointerMoved() else { return }
                onHover(index)
              }
          }
        }
        .padding(6)
      }
      .scrollIndicators(.never)
      .frame(height: CGFloat(min(count, Self.visibleRows)) * Self.rowHeight + 12)
      .onChange(of: selection) { _, index in proxy.scrollTo(index) }
    }
  }

  // MARK: - Footer

  private var footer: some View {
    HStack(spacing: 14) {
      if let message = model.message {
        Text(message)
          .foregroundStyle(.red)
          .lineLimit(2)
          .frame(maxWidth: .infinity, alignment: .leading)
      } else {
        Spacer(minLength: 0)
        switch model.mode {
        case .search:
          if let result = model.selectedResult {
            // A credential's copy action may name its value, which the row
            // already shows; the hint stays short.
            if let action = result.defaultAction {
              KeyHint(key: "↩", label: result.credential != nil ? "Copy Value" : action.title)
            }
            if let action = result.secondaryAction { KeyHint(key: "⌘↩", label: action.title) }
            if result.credential?.concealed == true { KeyHint(key: "⌥", label: "Reveal") }
            if result.credential != nil {
              KeyHint(key: "⇥", label: "Actions")
            } else {
              if result.completion != nil { KeyHint(key: "⇥", label: "Complete") }
              if result.actions.count + (result.secondaryAction == nil ? 0 : 1) > 1 {
                KeyHint(key: "⌘K", label: "Actions")
              }
            }
          }
        case .actions:
          KeyHint(key: "↩", label: "Run")
          KeyHint(key: "esc", label: "Back")
        case .unlock:
          EmptyView()
        }
      }
    }
    .font(.caption)
    .padding(.horizontal, 14)
    .frame(height: 30)
  }

  // MARK: - Unlock

  private var unlockPrompt: some View {
    VStack(spacing: 12) {
      Group {
        if let view = model.unlockView, let context = model.unlockContext {
          AuthenticationIcon(view: view)
            .id(ObjectIdentifier(context))
        } else {
          Image(systemName: "lock.fill")
            .font(.system(size: 28))
            .foregroundStyle(.secondary)
        }
      }
      .frame(width: 56, height: 56)

      Text("Unlock Axo Pass")
        .font(.headline)

      if let error = model.vaults.unlockError {
        Text(error)
          .foregroundStyle(.red)
          .multilineTextAlignment(.center)
      }

      if !model.vaults.isUnlocking {
        Button("Unlock", action: model.startUnlock)
          .buttonStyle(.borderedProminent)
      } else if model.vaults.offersPasswordUnlock {
        Button("Use Login Password…", action: model.unlockWithPassword)
          .buttonStyle(.link)
      }

      Text("Option-click the menu bar icon for more options.")
        .font(.caption)
        .foregroundStyle(.tertiary)
    }
    .padding(24)
    .frame(maxWidth: .infinity)
  }
}

// MARK: - Pieces

/// The search field. Arrow keys, Return, Escape and Command-K are taken by the
/// panel before they reach it.
private struct PaletteField: View {
  let prompt: String
  @Binding var text: String
  let prefix: String?
  @FocusState private var focused: Bool

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: "magnifyingglass")
        .foregroundStyle(.secondary)
      if let prefix {
        Text(prefix)
          .foregroundStyle(.secondary)
          .lineLimit(1)
        Image(systemName: "chevron.right")
          .font(.caption)
          .foregroundStyle(.tertiary)
      }
      TextField(prompt, text: $text)
        .textFieldStyle(.plain)
        .focused($focused)
    }
    .font(.system(size: 18))
    .padding(.horizontal, 14)
    .frame(height: 50)
    .task { focused = true }
  }
}

/// A result row. Items and credentials show their path, `vault › item` and
/// `vault › item › credential`, with the ancestors dimmed. A credential row
/// also shows its value.
private struct ResultRow: View {
  let result: PaletteResult
  let value: String?
  let isSelected: Bool

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: result.systemImage)
        .frame(width: 20)
        .foregroundStyle(
          result.kind == .vault ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.secondary))
      titleText
        .lineLimit(1)
        .truncationMode(.head)
        .layoutPriority(1)
      if let value {
        Text("›")
          .foregroundStyle(.tertiary)
        Text(value)
          .font(.system(.body, design: .monospaced))
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.tail)
      }
      if let subtitle = result.subtitle, !subtitle.isEmpty {
        Text(subtitle)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
      }
      Spacer(minLength: 8)
      // The path already says what a credential row is.
      if result.credential == nil {
        if let shortcut = result.shortcut {
          HStack(spacing: 3) {
            ForEach(Array(shortcut.enumerated()), id: \.offset) { _, key in
              KeyCap(key: key)
            }
          }
        } else {
          Text(result.kind.label)
            .font(.caption)
            .foregroundStyle(.tertiary)
        }
      }
    }
    .padding(.horizontal, 10)
    .frame(maxHeight: .infinity)
    .background(
      RoundedRectangle(cornerRadius: 6, style: .continuous)
        .fill(isSelected ? Color.accentColor.opacity(0.2) : .clear)
    )
    .contentShape(.rect)
  }

  private var titleText: Text {
    result.breadcrumb.reduce(Text("")) { text, name in
      text + Text(name).foregroundStyle(.secondary) + Text(" › ").foregroundStyle(.tertiary)
    } + Text(result.title)
  }
}

/// One key of a shortcut, drawn as a small keyboard cap.
private struct KeyCap: View {
  let key: Character

  var body: some View {
    Text(String(key))
      .font(.system(size: 11, weight: .medium, design: .rounded))
      .foregroundStyle(.secondary)
      .frame(minWidth: 18, minHeight: 18)
      .background(
        RoundedRectangle(cornerRadius: 4, style: .continuous)
          .fill(Color.primary.opacity(0.08))
      )
      .overlay(
        RoundedRectangle(cornerRadius: 4, style: .continuous)
          .strokeBorder(Color.primary.opacity(0.15), lineWidth: 0.5)
      )
  }
}

private struct ActionRow: View {
  let action: PaletteAction
  let isSelected: Bool

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: action.systemImage)
        .frame(width: 20)
        .foregroundStyle(.secondary)
      Text(action.title)
        .lineLimit(1)
      Spacer(minLength: 0)
    }
    .padding(.horizontal, 10)
    .frame(maxHeight: .infinity)
    .background(
      RoundedRectangle(cornerRadius: 6, style: .continuous)
        .fill(isSelected ? Color.accentColor.opacity(0.2) : .clear)
    )
    .contentShape(.rect)
  }
}

private struct KeyHint: View {
  let key: String
  let label: String

  var body: some View {
    HStack(spacing: 4) {
      Text(key)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 4)
        .background(Color.primary.opacity(0.08), in: RoundedRectangle(cornerRadius: 3))
      Text(label)
        .foregroundStyle(.secondary)
        .lineLimit(1)
    }
  }
}

/// A behind-window material that stays in its active appearance, since the
/// panel is key while Axo Pass itself is usually not the active app. The mask
/// rounds the material's corners, which `clipShape` does not do for an AppKit
/// view.
private struct PaletteBackground: NSViewRepresentable {
  static let cornerRadius: CGFloat = 12

  func makeNSView(context _: Context) -> NSVisualEffectView {
    let view = NSVisualEffectView()
    view.material = .popover
    view.blendingMode = .behindWindow
    view.state = .active
    view.maskImage = Self.makeMask()
    return view
  }

  func updateNSView(_: NSVisualEffectView, context _: Context) {}

  private static func makeMask() -> NSImage {
    let radius = cornerRadius
    let size = NSSize(width: radius * 2 + 1, height: radius * 2 + 1)
    let image = NSImage(size: size, flipped: false) { rect in
      NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius).fill()
      return true
    }
    image.capInsets = NSEdgeInsets(top: radius, left: radius, bottom: radius, right: radius)
    image.resizingMode = .stretch
    return image
  }
}
