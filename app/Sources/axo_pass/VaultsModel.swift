import Foundation
import Observation
import AxoPassFFI

@Observable
final class VaultsModel {
  private let core = AxoPass()

  var vaults: [VaultInfo] = []
  var selectedKey: String? = nil
  var loadError: String? = nil

  func reload() {
    do {
      vaults = try core.listVaults()
      loadError = nil
      if selectedKey == nil { selectedKey = vaults.first?.key }
    } catch {
      vaults = []
      loadError = String(describing: error)
    }
  }

  var selectedVault: VaultInfo? {
    guard let key = selectedKey else { return nil }
    return vaults.first { $0.key == key }
  }
}
