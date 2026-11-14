import AppKit
import AxoPassFFI
import Foundation
import QuickLook
import SwiftUI
import UniformTypeIdentifiers

// Support for file credentials: a credential of kind "file" holds a file whose
// contents are encrypted outside the vault file. The app never reads the
// credential value. Contents cross the FFI as paths, so a large file is never
// held in memory (`crates/ffi/src/files.rs`). A file credential takes no
// autofill role and is never copied as text.

/// Why the contents of a file credential could not be read.
enum FileFailure: Equatable {
  /// The contents are downloading to this Mac. Try again later.
  case pending
  /// The contents are not on this Mac and the synced folder does not hold
  /// them.
  case missing
  /// The stored contents fail verification.
  case damaged
  /// The authentication expired. The app locks.
  case authentication
  case other(String)

  init(_ error: Error) {
    switch error as? FfiError {
    case .FilePending: self = .pending
    case .FileMissing: self = .missing
    case .FileBlobMismatch: self = .damaged
    case .AuthExpired, .AuthCancelled: self = .authentication
    default: self = .other(String(describing: error))
    }
  }
}

extension FileSource {
  /// Source for the file at `url`. The MIME type comes from the file
  /// extension.
  init(url: URL) {
    self.init(
      path: url.path, name: url.lastPathComponent,
      mime: UTType(filenameExtension: url.pathExtension)?.preferredMIMEType)
  }
}

/// Decrypted copies of files made for Quick Look. Each copy is in its own
/// directory under a private directory in the temporary directory. A copy is
/// removed when its preview closes, and all of them when the app locks and
/// when it starts.
enum FilePreviews {
  private static var root: URL {
    FileManager.default.temporaryDirectory.appendingPathComponent(
      "axo-pass-previews", isDirectory: true)
  }

  /// A new path for a decrypted copy named `name`. The directory is private to
  /// the owner. The file does not exist yet.
  static func makeFileURL(name: String) throws -> URL {
    let directory = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    return directory.appendingPathComponent(safeFileName(name))
  }

  /// Remove the copy at `url` and its directory.
  static func remove(_ url: URL) {
    guard url.path.hasPrefix(root.path + "/") else { return }
    try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
  }

  /// Remove every copy.
  static func removeAll() {
    try? FileManager.default.removeItem(at: root)
  }
}

/// `name` as a single path component. Separators become `-`.
func safeFileName(_ name: String) -> String {
  let cleaned = name.map { $0 == "/" || $0 == ":" || $0 == "\0" ? "-" : $0 }
  let result = String(cleaned).trimmingCharacters(in: .whitespaces)
  return result.isEmpty || result == "." || result == ".." ? "file" : result
}

/// Credential key for a file named `name` that is not in `taken`. The name is
/// lowercased, with runs of characters other than letters and digits as `-`.
/// A key starts with a letter, ends with a letter or digit, and has at least
/// three characters, so a name that does not fit gets a `file-` prefix. A
/// taken key gets a numeric suffix.
func fileCredentialKey(for name: String, taken: Set<String>) -> String {
  var slug = ""
  for scalar in name.lowercased().unicodeScalars {
    if scalar.isASCII && CharacterSet.alphanumerics.contains(scalar) {
      slug.unicodeScalars.append(scalar)
    } else if !slug.hasSuffix("-") {
      slug.append("-")
    }
  }
  slug = slug.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
  if slug.isEmpty {
    slug = "file"
  } else if !(slug.first?.isLetter ?? false) {
    slug = "file-\(slug)"
  }
  if slug.count < 3 { slug = "file-\(slug)" }
  let base = slug
  var candidate = base
  var n = 2
  while taken.contains(candidate) {
    candidate = "\(base)-\(n)"
    n += 1
  }
  return candidate
}

extension FileInfo {
  /// Size and type, such as `12 KB · PDF document`.
  var detail: String {
    let size = ByteCountFormatter.string(fromByteCount: Int64(clamping: size), countStyle: .file)
    guard let type = contentType?.localizedDescription else { return size }
    return "\(size) · \(type)"
  }

  /// Type from the recorded MIME type, or else the file extension.
  var contentType: UTType? {
    if let mime, let type = UTType(mimeType: mime) { return type }
    let ext = (name as NSString).pathExtension
    return ext.isEmpty ? nil : UTType(filenameExtension: ext)
  }

  /// SF Symbol for the type.
  var symbolName: String {
    guard let type = contentType else { return "doc" }
    if type.conforms(to: .image) { return "photo" }
    if type.conforms(to: .pdf) { return "doc.richtext" }
    if type.conforms(to: .audio) { return "waveform" }
    if type.conforms(to: .movie) { return "film" }
    if type.conforms(to: .archive) { return "doc.zipper" }
    if type.conforms(to: .text) { return "doc.text" }
    return "doc"
  }
}

/// Details and actions of a file credential, shown in place of a value.
struct FileBox: View {
  let file: FileInfo?
  let failure: FileFailure?
  let isBusy: Bool
  let onPreview: () -> Void
  let onSave: () -> Void
  let onReplace: () -> Void
  let onTrash: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack(spacing: 10) {
        Image(systemName: file?.symbolName ?? "exclamationmark.triangle")
          .font(.title2)
          .foregroundStyle(.secondary)
          .frame(width: 28)
        VStack(alignment: .leading, spacing: 2) {
          Text(file?.name ?? "Unreadable file record")
            .lineLimit(1)
            .truncationMode(.middle)
            .textSelection(.enabled)
          if let file {
            Text(file.detail).font(.caption).foregroundStyle(.secondary)
          }
        }
        Spacer(minLength: 0)
        if isBusy { ProgressView().controlSize(.small) }
      }
      status
      HStack(spacing: 8) {
        Button("Preview", action: onPreview)
          .help("Open in Quick Look")
        Button("Save…", action: onSave)
          .help("Save a copy to disk")
        Button("Replace…", action: onReplace)
          .help("Replace the file. The current file stays in the previous values.")
        Spacer(minLength: 0)
        Button("Move to Trash", role: .destructive, action: onTrash)
      }
      .controlSize(.small)
      .disabled(isBusy)
      .disabled(file == nil)
    }
    .padding(.vertical, 8)
    .padding(.horizontal, 10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
  }

  /// State of the contents. Nothing shows for a file that is on this Mac.
  @ViewBuilder
  private var status: some View {
    switch failure {
    case .pending:
      Label("Downloading to this Mac. Try again in a moment.", systemImage: "icloud.and.arrow.down")
        .font(.caption)
        .foregroundStyle(.secondary)
    case .missing:
      Label(
        "The contents are not on this Mac. They are not in the synced folder, or were not in the imported bundle.",
        systemImage: "questionmark.folder"
      )
      .font(.caption)
      .foregroundStyle(.orange)
      .fixedSize(horizontal: false, vertical: true)
    case .damaged:
      Label(
        "The stored contents are damaged and fail verification.",
        systemImage: "exclamationmark.triangle.fill"
      )
      .font(.caption)
      .foregroundStyle(.red)
    case .other(let message):
      Text(message).font(.caption).foregroundStyle(.red).textSelection(.enabled)
    case .authentication, nil:
      if file == nil {
        Text("The file record could not be read.").font(.caption).foregroundStyle(.red)
      } else if file?.local == false {
        Label(
          "Not downloaded yet. It downloads when you open or save it.",
          systemImage: "icloud.and.arrow.down"
        )
        .font(.caption)
        .foregroundStyle(.secondary)
      }
    }
  }
}

extension CredentialList {
  /// Ask for a file and add it to the item as a new file credential.
  func addFile() {
    guard let url = chooseFile(prompt: "Add") else { return }
    Task {
      if let message = await model.addFile(vaultKey: vaultKey, itemKey: item.key, url: url) {
        listError = message
      }
    }
  }

  /// Ask for a file to replace the file of `cred` with.
  func replaceFile(_ cred: CredentialInfo) {
    guard let url = chooseFile(prompt: "Replace") else { return }
    Task {
      fileBusy.insert(cred.key)
      defer { fileBusy.remove(cred.key) }
      errors[cred.key] = await model.replaceFile(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key, url: url)
    }
  }

  /// Ask for a destination and save the file of `cred` there.
  func saveFile(_ cred: CredentialInfo) {
    let panel = NSSavePanel()
    panel.nameFieldStringValue = safeFileName(cred.file?.name ?? cred.title)
    panel.isExtensionHidden = false
    guard panel.runModal() == .OK, let url = panel.url else { return }
    Task {
      fileBusy.insert(cred.key)
      defer { fileBusy.remove(cred.key) }
      errors[cred.key] = nil
      if case .other(let message)? = await model.saveFile(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key, to: url)
      {
        errors[cred.key] = message
      }
    }
  }

  /// Decrypt the file of `cred` to a temporary copy and open Quick Look on it.
  func previewFile(_ cred: CredentialInfo) {
    Task {
      fileBusy.insert(cred.key)
      defer { fileBusy.remove(cred.key) }
      errors[cred.key] = nil
      previewURL = await model.previewFile(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key,
        name: cred.file?.name ?? cred.title)
    }
  }

  /// Remove the temporary copy of a closed preview.
  func previewClosed(_ url: URL?) {
    if let url { FilePreviews.remove(url) }
  }

  private func chooseFile(prompt: String) -> URL? {
    let panel = NSOpenPanel()
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.prompt = prompt
    return panel.runModal() == .OK ? panel.url : nil
  }
}
