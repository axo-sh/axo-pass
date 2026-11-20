import AppKit
import SwiftUI

extension View {
  /// Collapse column `index` of the enclosing `NavigationSplitView` if
  /// `collapsed`, and expand it otherwise.
  ///
  /// SwiftUI has no API to hide only the middle column of a three-column
  /// split view. This finds the `NSSplitViewController` that SwiftUI creates
  /// and sets `isCollapsed` on the split item. It depends on that AppKit
  /// structure, so it does nothing if the structure differs.
  func splitColumnCollapsed(_ collapsed: Bool, index: Int) -> some View {
    background(SplitColumnCollapser(collapsed: collapsed, index: index))
  }
}

private struct SplitColumnCollapser: NSViewRepresentable {
  let collapsed: Bool
  let index: Int

  func makeNSView(context: Context) -> NSView {
    NSView(frame: .zero)
  }

  func updateNSView(_ view: NSView, context: Context) {
    // Apply in the same update so no frame shows the old layout. On the first
    // pass the view joins the hierarchy after this returns, so apply later.
    if view.window != nil {
      apply(from: view)
    } else {
      DispatchQueue.main.async {
        apply(from: view)
      }
    }
  }

  private func apply(from view: NSView) {
    guard let controller = splitViewController(above: view),
      controller.splitViewItems.indices.contains(index)
    else { return }
    let item = controller.splitViewItems[index]
    guard item.isCollapsed != collapsed else { return }
    item.canCollapse = true
    item.isCollapsed = collapsed
  }

  /// Nearest split view controller with three or more items above `view`.
  private func splitViewController(above view: NSView) -> NSSplitViewController? {
    var current = view.superview
    while let candidate = current {
      if let splitView = candidate as? NSSplitView,
        let controller = splitView.delegate as? NSSplitViewController,
        controller.splitViewItems.count >= 3
      {
        return controller
      }
      current = candidate.superview
    }
    return nil
  }
}
