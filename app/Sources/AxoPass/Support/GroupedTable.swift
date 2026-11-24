import SwiftUI

/// Horizontal inset of table rows, dividers, and table captions.
let tableInset: CGFloat = 10

/// Rows in a rounded, bordered box, separated by dividers.
struct GroupedTable<Data: RandomAccessCollection, ID: Hashable, RowContent: View>: View {
  let data: Data
  let id: KeyPath<Data.Element, ID>
  let row: (Data.Element) -> RowContent

  init(
    _ data: Data, id: KeyPath<Data.Element, ID>,
    @ViewBuilder row: @escaping (Data.Element) -> RowContent
  ) {
    self.data = data
    self.id = id
    self.row = row
  }

  var body: some View {
    VStack(spacing: 0) {
      let firstID = data.first?[keyPath: id]
      ForEach(data, id: id) { element in
        if element[keyPath: id] != firstID {
          Divider().padding(.leading, tableInset)
        }
        row(element)
          .padding(.vertical, 7)
          .padding(.horizontal, tableInset)
      }
    }
    .background(.quinary, in: RoundedRectangle(cornerRadius: 8))
    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.separator))
  }
}
