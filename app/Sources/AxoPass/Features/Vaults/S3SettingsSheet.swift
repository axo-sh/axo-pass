import AxoPassFFI
import SwiftUI

/// Sheet that sets an S3-compatible bucket as the synced location of the app.
/// The bucket is tested before it can be saved. The secret access key is stored
/// in the keychain and is never shown again.
struct S3SettingsSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(\.dismiss) private var dismiss

  /// Returns to the location list. Nil if the sheet stands alone, which shows
  /// Cancel in its place.
  var onBack: (() -> Void)? = nil

  @State private var endpoint = ""
  @State private var region = ""
  @State private var bucket = ""
  @State private var prefix = ""
  @State private var accessKeyId = ""
  @State private var secretAccessKey = ""

  @State private var isTesting = false
  @State private var isSaving = false
  /// Settings that passed the test, as `fingerprint`. A change to any field
  /// makes the test stale.
  @State private var passedFingerprint: String? = nil
  @State private var testNote: String? = nil
  @State private var error: String? = nil

  private var settings: S3SettingsInput {
    S3SettingsInput(
      endpoint: endpoint.trimmingCharacters(in: .whitespacesAndNewlines),
      region: region.trimmingCharacters(in: .whitespacesAndNewlines),
      bucket: bucket.trimmingCharacters(in: .whitespacesAndNewlines),
      prefix: prefix.trimmingCharacters(in: .whitespacesAndNewlines),
      accessKeyId: accessKeyId.trimmingCharacters(in: .whitespacesAndNewlines),
      secretAccessKey: secretAccessKey)
  }

  private var fingerprint: String {
    let s = settings
    return [s.endpoint, s.region, s.bucket, s.prefix, s.accessKeyId, s.secretAccessKey]
      .joined(separator: "\n")
  }

  private var isComplete: Bool {
    let s = settings
    return ![s.endpoint, s.region, s.bucket, s.accessKeyId, s.secretAccessKey].contains(
      where: \.isEmpty)
  }

  private var isTested: Bool { passedFingerprint == fingerprint }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Sync with an S3 Bucket").font(.headline)

      Form {
        TextField("Endpoint:", text: $endpoint, prompt: Text("https://s3.us-east-1.amazonaws.com"))
        TextField("Region:", text: $region, prompt: Text("us-east-1, or auto for R2"))
        TextField("Bucket:", text: $bucket)
        TextField("Prefix:", text: $prefix, prompt: Text("Optional"))
        TextField("Access key ID:", text: $accessKeyId)
        SecureField("Secret access key:", text: $secretAccessKey)
        LabeledContent("") {
          Text(
            "Use a key limited to this bucket and prefix with list, get, put, and delete access. Turn on bucket versioning or object lock so a leaked key cannot erase the bucket."
          )
          .font(.caption)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
          .frame(maxWidth: .infinity, alignment: .leading)
        }
      }
      .disabled(isSaving)

      if let error { SyncErrorLabel(message: error) }
      if let testNote {
        Label(testNote, systemImage: "checkmark.circle.fill")
          .font(.caption)
          .foregroundStyle(.green)
          .fixedSize(horizontal: false, vertical: true)
      }

      HStack {
        if isTesting || isSaving { ProgressView().controlSize(.small) }
        Spacer()
        if let onBack {
          Button("Back") { onBack() }
            .keyboardShortcut(.cancelAction)
            .disabled(isSaving)
        } else {
          Button("Cancel") { dismiss() }
            .keyboardShortcut(.cancelAction)
        }
        Button("Test Connection") { test() }
          .disabled(!isComplete || isTesting || isSaving)
        Button("Save") { save() }
          .keyboardShortcut(.defaultAction)
          .disabled(!isTested || isTesting || isSaving)
      }
    }
    .padding(20)
    .frame(width: 520)
    .onChange(of: fingerprint) {
      testNote = nil
      error = nil
    }
    .task { await loadSaved() }
  }

  /// Fill the fields from the saved settings. The secret is not saved in the
  /// form, so it is entered again to test or save.
  private func loadSaved() async {
    guard let saved = try? await sync.loadS3() else { return }
    endpoint = saved.endpoint
    region = saved.region
    bucket = saved.bucket
    prefix = saved.prefix
    accessKeyId = saved.accessKeyId
  }

  private func test() {
    error = nil
    testNote = nil
    isTesting = true
    let tested = fingerprint
    let input = settings
    Task {
      defer { isTesting = false }
      do {
        let report = try await sync.testS3(input)
        passedFingerprint = tested
        testNote =
          report.listAttempts > 1
          ? "Connection works. The listing showed a new file after \(report.listAttempts) reads, so changes can take a moment to appear."
          : "Connection works."
      } catch {
        self.error = Self.message(for: error)
      }
    }
  }

  private func save() {
    error = nil
    isSaving = true
    let input = settings
    Task {
      defer { isSaving = false }
      do {
        try await sync.saveS3(input)
        dismiss()
      } catch {
        self.error = Self.message(for: error)
      }
    }
  }

  /// Error text without the case name wrapped around it.
  private static func message(for error: Error) -> String {
    switch error {
    case let error as FfiError:
      switch error {
      case .NotFound(let message), .InvalidInput(let message), .Internal(let message):
        return message
      default:
        return error.localizedDescription
      }
    default:
      return String(describing: error)
    }
  }
}
