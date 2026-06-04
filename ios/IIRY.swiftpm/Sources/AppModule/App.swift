import IIRYCore
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers
import UIKit

@main
struct IIRYApp: App {
    @State private var model = IIRYAppModel()

    var body: some Scene {
        WindowGroup {
            IIRYRootView(model: model)
                .onOpenURL { url in
                    Task { await model.handle(url: url) }
                }
        }
    }
}

extension UTType {
    static let iiryProof = UTType(exportedAs: IIRYConstants.carrierUTType)
}

@Observable
@MainActor
final class IIRYAppModel {
    static let defaultServiceBaseURL = "https://iiry.ndurner.de"
    private static let serviceBaseURLKey = "iiry.serviceBaseURL"

    var serviceBaseURL: String
    var requestText: String
    var carrier: IIRYCarrier?
    var pendingSession: PresentationSession?
    var verificationReport: IIRYVerificationReport?
    var selectedImage: UIImage?
    var statusMessage: String?
    var errorMessage: String?
    var isBusy = false
    var showsImporter = false
    var showsSettings = false
    var shareItem: IIRYShareItem?

    init() {
        self.serviceBaseURL = UserDefaults.standard.string(forKey: Self.serviceBaseURLKey) ?? Self.defaultServiceBaseURL
        self.requestText = (try? IIRYRequestText.make()) ?? "Is it really you?"
    }

    var hasPreparedProof: Bool {
        carrier != nil
    }

    func refreshRequestText() {
        requestText = (try? IIRYRequestText.make()) ?? requestText
    }

    func importFile(_ url: URL) async {
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped {
                url.stopAccessingSecurityScopedResource()
            }
        }

        do {
            let data = try Data(contentsOf: url)
            if url.pathExtension.lowercased() == IIRYConstants.carrierExtension {
                do {
                    let importedCarrier = try IIRYProofBuilder.decodeCarrier(data)
                    carrier = importedCarrier
                    selectedImage = UIImage(data: try Base64URL.decode(importedCarrier.imageB64URL))
                    verificationReport = try IIRYVerifier.verifyCarrier(importedCarrier)
                    statusMessage = "Proof opened"
                } catch {
                    try importC2PAJPEG(data, fileName: url.lastPathComponent)
                }
            } else {
                try prepareImage(data)
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func importPhotoItem(_ item: PhotosPickerItem?) async {
        guard let item else {
            return
        }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            guard let data = try await item.loadTransferable(type: Data.self) else {
                throw IIRYError.invalidCarrier("Selected photo did not provide image data")
            }
            try prepareImage(data)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func shareRequest() {
        refreshRequestText()
        shareItem = IIRYShareItem(activityItems: [requestText])
    }

    func saveServiceEndpoint(_ value: String) {
        do {
            let normalized = try normalizedServiceEndpoint(value)
            serviceBaseURL = normalized
            UserDefaults.standard.set(normalized, forKey: Self.serviceBaseURLKey)
            showsSettings = false
            statusMessage = "Endpoint updated"
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func resetServiceEndpoint() {
        serviceBaseURL = Self.defaultServiceBaseURL
        UserDefaults.standard.removeObject(forKey: Self.serviceBaseURLKey)
        showsSettings = false
        statusMessage = "Endpoint reset"
    }

    func shareCarrier() {
        guard let carrier else {
            errorMessage = "No IIRY proof is ready."
            return
        }
        do {
            let data = try IIRYProofBuilder.carrierData(carrier)
            let url = try writeTempData(data, fileName: carrier.suggestedFileName)
            shareItem = IIRYShareItem(activityItems: [url])
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func startWalletFlow() async {
        guard let carrier else {
            errorMessage = "Import a JPEG first."
            return
        }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let session = try await createPresentationSession(for: carrier)
            pendingSession = session
            statusMessage = "Opening wallet to commit"
            guard let walletURL = URL(string: session.openWalletURL) else {
                throw IIRYError.commandFailed("Invalid wallet URL from service")
            }
            await UIApplication.shared.open(walletURL)
        } catch {
            errorMessage = userFacingMessage(for: error)
        }
    }

    func handle(url: URL) async {
        if url.isFileURL {
            await importFile(url)
            return
        }
        if url.scheme == "iiry", url.host == "share-image" {
            await importSharedImage(url)
            return
        }
        guard url.scheme == "iiry", url.host == "wallet-callback" else {
            errorMessage = "Unsupported URL: \(url.absoluteString)"
            return
        }
        let state = url.pathComponents.dropFirst().first ?? ""
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let token = components?.queryItems?.first(where: { $0.name == "token" })?.value
        let base = components?.queryItems?.first(where: { $0.name == "base" })?.value
        if let base, !base.isEmpty {
            serviceBaseURL = base.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        }
        guard !state.isEmpty, let token, !token.isEmpty else {
            errorMessage = "Wallet callback did not include the session token."
            return
        }
        await fetchWalletResponse(state: state, token: token)
    }

    func fetchWalletResponse(state: String, token: String) async {
        guard let carrier else {
            errorMessage = "No local proof is waiting for this wallet response."
            return
        }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let response = try await walletResponse(state: state, token: token)
            let updated = try IIRYProofBuilder.attachPresentation(
                carrier: carrier,
                decodedResponseJSON: response.decodedResponseJSON,
                walletVerification: response.verification
            )
            self.carrier = updated
            self.selectedImage = UIImage(data: try Base64URL.decode(updated.imageB64URL))
            self.verificationReport = try IIRYVerifier.verifyCarrier(updated)
            self.statusMessage = "Wallet proof attached"
            do {
                let signed = try IIRYC2PAAssetProcessor.signJPEG(carrier: updated)
                self.verificationReport = try IIRYC2PAAssetProcessor.verifyJPEG(signed.jpegData)
                let url = try writeTempData(signed.jpegData, fileName: updated.suggestedFileName)
                self.statusMessage = "C2PA JPEG ready"
                self.shareItem = IIRYShareItem(activityItems: [url])
            } catch {
                self.errorMessage = "C2PA signing unavailable: \(error.localizedDescription)"
                shareCarrier()
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func saveReceiptToPhotos() {
        guard let carrier, let image = selectedImage, let report = verificationReport else {
            errorMessage = "No verification receipt is ready."
            return
        }
        let renderer = ImageRenderer(content: ReceiptSnapshotView(carrier: carrier, image: image, report: report))
        renderer.scale = UIScreen.main.scale
        guard let output = renderer.uiImage else {
            errorMessage = "Could not render receipt."
            return
        }
        UIImageWriteToSavedPhotosAlbum(output, nil, nil, nil)
        statusMessage = "Receipt saved"
    }

    private func createPresentationSession(for carrier: IIRYCarrier) async throws -> PresentationSession {
        guard let url = URL(string: "\(serviceBaseURL)/api/presentations") else {
            throw IIRYError.commandFailed("Invalid service URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "nonce": carrier.proof.openID4VP.nonce
        ])
        let (data, response) = try await URLSession.shared.data(for: request)
        try validateHTTP(response, data: data)
        return try JSONDecoder().decode(PresentationSession.self, from: data)
    }

    private func importSharedImage(_ url: URL) async {
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            guard let pasteboardName = components?.queryItems?.first(where: { $0.name == "pasteboard" })?.value,
                  !pasteboardName.isEmpty else {
                throw IIRYError.invalidCarrier("Share extension did not include image handoff data")
            }
            let type = components?.queryItems?.first(where: { $0.name == "type" })?.value ?? UTType.data.identifier
            guard let pasteboard = UIPasteboard(name: UIPasteboard.Name(rawValue: pasteboardName), create: false) else {
                throw IIRYError.invalidCarrier("Shared image handoff expired")
            }
            guard let data = pasteboard.data(forPasteboardType: type)
                ?? pasteboard.data(forPasteboardType: UTType.jpeg.identifier)
                ?? pasteboard.data(forPasteboardType: UTType.png.identifier)
                ?? pasteboard.data(forPasteboardType: UTType.data.identifier) else {
                throw IIRYError.invalidCarrier("Shared image handoff did not contain image data")
            }
            try prepareImage(data)
            pasteboard.items = []
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func importC2PAJPEG(_ data: Data, fileName: String) throws {
        let manifestReport = try IIRYC2PAAssetProcessor.readManifestReport(fromJPEGData: data)
        let proof = try IIRYC2PAInspectionVerifier.extractProofBundle(fromDetailedJSON: manifestReport)
        let report = try IIRYC2PAAssetProcessor.verifyJPEG(data)
        let visualData = try IIRYC2PAAssetProcessor.visualJPEGData(from: data)
        carrier = IIRYCarrier(
            suggestedFileName: fileName,
            imageB64URL: Base64URL.encode(visualData),
            proof: proof
        )
        selectedImage = UIImage(data: visualData)
        verificationReport = report
        pendingSession = nil
        statusMessage = "C2PA proof opened"
    }

    private func prepareImage(_ data: Data) throws {
        let jpegData = try normalizedJPEGData(from: data)
        let prepared = try IIRYProofBuilder.prepare(imageData: jpegData)
        carrier = prepared.carrier
        selectedImage = UIImage(data: jpegData)
        verificationReport = nil
        pendingSession = nil
        statusMessage = isJPEG(data) ? "Image commitment prepared" : "Image converted to JPEG and prepared"
    }

    private func normalizedJPEGData(from data: Data) throws -> Data {
        if isJPEG(data) {
            return data
        }
        guard let image = UIImage(data: data),
              let jpeg = image.jpegData(compressionQuality: 0.92) else {
            throw IIRYError.invalidCarrier("Selected file is not a readable image")
        }
        return jpeg
    }

    private func isJPEG(_ data: Data) -> Bool {
        data.count >= 2 && data[0] == 0xff && data[1] == 0xd8
    }

    private func walletResponse(state: String, token: String) async throws -> WalletResponsePayload {
        guard let url = URL(string: "\(serviceBaseURL)/api/presentations/\(state)/wallet-response?token=\(token)") else {
            throw IIRYError.commandFailed("Invalid wallet response URL")
        }
        let (data, response) = try await URLSession.shared.data(from: url)
        try validateHTTP(response, data: data)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let decodedResponse = object["decoded_response"] else {
            throw IIRYError.commandFailed("Service response did not include decoded_response")
        }
        let decodedResponseJSON = try JSONCoding.objectData(decodedResponse)
        var verification: WalletVerificationSummary?
        if let verificationObject = object["verification"] {
            let verificationData = try JSONCoding.objectData(verificationObject)
            verification = try JSONDecoder().decode(WalletVerificationSummary.self, from: verificationData)
        }
        return WalletResponsePayload(decodedResponseJSON: decodedResponseJSON, verification: verification)
    }

    private func validateHTTP(_ response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else {
            throw IIRYError.commandFailed("No HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                let error = object["error"] as? String ?? "HTTP \(http.statusCode)"
                let details = object["details"] as? [String] ?? []
                let detailText = details.isEmpty ? error : "\(error): \(details.joined(separator: "; "))"
                throw IIRYError.commandFailed(detailText)
            }
            let detail = String(data: data, encoding: .utf8) ?? "HTTP \(http.statusCode)"
            throw IIRYError.commandFailed(detail)
        }
    }

    private func userFacingMessage(for error: Error) -> String {
        if let urlError = error as? URLError, urlError.isCertificateOrTLSError {
            return "The wallet service TLS certificate is not valid for \(serviceBaseURL). Fix the HTTPS certificate before using wallet handoff."
        }
        return error.localizedDescription
    }

    private func normalizedServiceEndpoint(_ value: String) throws -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased(),
              let host = components.host,
              !host.isEmpty else {
            throw IIRYError.commandFailed("Enter a valid service URL.")
        }
        let localHosts = ["localhost", "127.0.0.1", "::1"]
        guard scheme == "https" || (scheme == "http" && localHosts.contains(host.lowercased())) else {
            throw IIRYError.commandFailed("Use HTTPS for remote wallet service endpoints.")
        }
        guard components.path.isEmpty || components.path == "/" else {
            throw IIRYError.commandFailed("Enter the service origin only, without /api paths.")
        }
        return trimmed
    }

    private func writeTempData(_ data: Data, fileName: String) throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("iiry-share", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(fileName)
        try data.write(to: url, options: .atomic)
        return url
    }
}

struct PresentationSession: Decodable, Equatable {
    let state: String
    let apiToken: String
    let openWalletURL: String

    enum CodingKeys: String, CodingKey {
        case state
        case apiToken = "api_token"
        case openWalletURL = "open_wallet_url"
    }
}

struct WalletResponsePayload {
    let decodedResponseJSON: Data
    let verification: WalletVerificationSummary?
}

struct IIRYShareItem: Identifiable {
    let id = UUID()
    let activityItems: [Any]
}

struct IIRYRootView: View {
    @Bindable var model: IIRYAppModel

    var body: some View {
        ZStack {
            IIRYBackdrop()
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 18) {
                    HeroPanel(model: model)
                    if let carrier = model.carrier, let image = model.selectedImage {
                        VerificationPanel(model: model, carrier: carrier, image: image)
                    } else {
                        IntakePanel(model: model)
                    }
                    StatusPanel(model: model)
                }
                .padding(.horizontal, 18)
                .padding(.top, 18)
                .padding(.bottom, 34)
            }
        }
        .fileImporter(
            isPresented: $model.showsImporter,
            allowedContentTypes: [.image, .iiryProof],
            allowsMultipleSelection: false
        ) { result in
            Task {
                if case .success(let urls) = result, let url = urls.first {
                    await model.importFile(url)
                }
            }
        }
        .sheet(item: $model.shareItem) { item in
            ShareSheet(activityItems: item.activityItems)
        }
        .sheet(isPresented: $model.showsSettings) {
            EndpointSettingsView(
                currentEndpoint: model.serviceBaseURL,
                onSave: { model.saveServiceEndpoint($0) },
                onReset: { model.resetServiceEndpoint() }
            )
            .presentationDetents([.medium])
        }
    }
}

struct HeroPanel: View {
    @Bindable var model: IIRYAppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            IrinaLensArtwork()
                .frame(height: 220)
                .clipShape(RoundedRectangle(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 7) {
                Text("IIRY")
                    .font(.system(size: 46, weight: .black, design: .rounded))
                    .foregroundStyle(IIRYPalette.ink)

                Text("seeks to help confirm Is It Really You?")
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                    .foregroundStyle(IIRYPalette.plum)

                Text("A wallet-backed signal for challenged images: fresh presentation, image binding, and verification checks.")
                    .font(.system(size: 15, weight: .medium, design: .rounded))
                    .foregroundStyle(IIRYPalette.ink.opacity(0.70))
                    .lineSpacing(2)
            }

            HStack(spacing: 10) {
                Button {
                    model.shareRequest()
                } label: {
                    Label("Share request", systemImage: "paperplane")
                }
                .buttonStyle(IIRYPrimaryButtonStyle())

                Button {
                    model.refreshRequestText()
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .frame(width: 44, height: 44)
                }
                .buttonStyle(IIRYIconButtonStyle())
                .accessibilityLabel("Refresh request nonce")

                Button {
                    model.showsSettings = true
                } label: {
                    Image(systemName: "gearshape")
                        .frame(width: 44, height: 44)
                }
                .buttonStyle(IIRYIconButtonStyle())
                .accessibilityLabel("Settings")
            }

            Text(model.requestText)
                .font(.system(size: 14, weight: .semibold, design: .monospaced))
                .foregroundStyle(IIRYPalette.ink.opacity(0.72))
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(IIRYPalette.panel.opacity(0.78), in: RoundedRectangle(cornerRadius: 8))
        }
        .padding(14)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))
    }
}

struct EndpointSettingsView: View {
    let currentEndpoint: String
    let onSave: (String) -> Void
    let onReset: () -> Void
    @State private var endpoint: String
    @Environment(\.dismiss) private var dismiss

    init(currentEndpoint: String, onSave: @escaping (String) -> Void, onReset: @escaping () -> Void) {
        self.currentEndpoint = currentEndpoint
        self.onSave = onSave
        self.onReset = onReset
        self._endpoint = State(initialValue: currentEndpoint)
    }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                SectionTitle(title: "Settings", detail: "Wallet service")

                VStack(alignment: .leading, spacing: 8) {
                    Text("API endpoint")
                        .font(.system(size: 13, weight: .semibold, design: .rounded))
                        .foregroundStyle(IIRYPalette.ink.opacity(0.70))
                    TextField("https://iiry.ndurner.de", text: $endpoint)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .font(.system(size: 15, weight: .semibold, design: .monospaced))
                        .padding(12)
                        .background(Color.white.opacity(0.70), in: RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))
                }

                Text("Use the service origin only. IIRY appends `/api/presentations` for the wallet flow.")
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(IIRYPalette.ink.opacity(0.62))

                HStack(spacing: 10) {
                    Button {
                        onSave(endpoint)
                    } label: {
                        Label("Save", systemImage: "checkmark")
                    }
                    .buttonStyle(IIRYPrimaryButtonStyle())

                    Button {
                        onReset()
                    } label: {
                        Image(systemName: "arrow.uturn.backward")
                            .frame(width: 44, height: 44)
                    }
                    .buttonStyle(IIRYIconButtonStyle())
                    .accessibilityLabel("Reset endpoint")
                }

                Spacer(minLength: 0)
            }
            .padding(18)
            .background(IIRYBackdrop())
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .accessibilityLabel("Close settings")
                }
            }
        }
    }
}

struct IntakePanel: View {
    @Bindable var model: IIRYAppModel
    @State private var photoItem: PhotosPickerItem?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionTitle(title: "Prepare Image", detail: "Photos or file")
            PhotosPicker(selection: $photoItem, matching: .images, photoLibrary: .shared()) {
                Label("Choose from Photos", systemImage: "photo.badge.plus")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(IIRYSecondaryButtonStyle())
            .onChange(of: photoItem) { _, newValue in
                Task {
                    await model.importPhotoItem(newValue)
                    photoItem = nil
                }
            }

            Button {
                model.showsImporter = true
            } label: {
                Label("Open IIRY or image file", systemImage: "folder")
            }
            .buttonStyle(IIRYSecondaryButtonStyle())
        }
        .modifier(IIRYPanelStyle())
    }
}

struct VerificationPanel: View {
    @Bindable var model: IIRYAppModel
    let carrier: IIRYCarrier
    let image: UIImage

    var body: some View {
        let hasProof = model.verificationReport != nil

        VStack(alignment: .leading, spacing: 14) {
            SectionTitle(title: hasProof ? "Verification" : "Commitment", detail: carrier.suggestedFileName)

            Image(uiImage: image)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: .infinity)
                .background(Color.black.opacity(0.04))
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))

            if let report = model.verificationReport {
                VStack(spacing: 8) {
                    ForEach(report.checks) { check in
                        CheckRow(check: check)
                    }
                }
            }

            HStack(spacing: 10) {
                Button {
                    Task { await model.startWalletFlow() }
                } label: {
                    Label("Commit to it", systemImage: "wallet.pass")
                }
                .buttonStyle(IIRYPrimaryButtonStyle())
                .disabled(model.isBusy)

                if hasProof {
                    Button {
                        model.shareCarrier()
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                            .frame(width: 44, height: 44)
                    }
                    .buttonStyle(IIRYIconButtonStyle())
                    .accessibilityLabel("Share IIRY proof")

                    Button {
                        model.saveReceiptToPhotos()
                    } label: {
                        Image(systemName: "square.and.arrow.down")
                            .frame(width: 44, height: 44)
                    }
                    .buttonStyle(IIRYIconButtonStyle())
                    .accessibilityLabel("Save receipt")
                }
            }
        }
        .modifier(IIRYPanelStyle())
    }
}

extension URLError {
    var isCertificateOrTLSError: Bool {
        switch code {
        case .secureConnectionFailed,
             .serverCertificateHasBadDate,
             .serverCertificateUntrusted,
             .serverCertificateHasUnknownRoot,
             .serverCertificateNotYetValid,
             .clientCertificateRejected,
             .clientCertificateRequired:
            return true
        default:
            return false
        }
    }
}

struct StatusPanel: View {
    @Bindable var model: IIRYAppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if model.isBusy {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Working")
                }
                .font(.system(size: 14, weight: .semibold, design: .rounded))
                .foregroundStyle(IIRYPalette.ink.opacity(0.72))
            }
            if let status = model.statusMessage {
                Label(status, systemImage: "checkmark.seal")
                    .foregroundStyle(IIRYPalette.green)
            }
            if let error = model.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(IIRYPalette.rust)
            }
        }
        .font(.system(size: 14, weight: .semibold, design: .rounded))
        .frame(maxWidth: .infinity, alignment: .leading)
        .modifier(IIRYPanelStyle())
    }
}

struct CheckRow: View {
    let check: IIRYVerificationCheck

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: check.passed ? "checkmark.seal.fill" : "xmark.seal")
                .foregroundStyle(check.passed ? IIRYPalette.green : IIRYPalette.rust)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(check.label)
                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                    .foregroundStyle(IIRYPalette.ink)
                if let detail = check.detail, !detail.isEmpty {
                    Text(detail)
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .foregroundStyle(IIRYPalette.ink.opacity(0.54))
                }
            }
            Spacer(minLength: 8)
        }
        .padding(10)
        .background(Color.white.opacity(0.58), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct SectionTitle: View {
    let title: String
    let detail: String?

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title)
                .font(.system(size: 19, weight: .bold, design: .rounded))
                .foregroundStyle(IIRYPalette.ink)
            Spacer(minLength: 10)
            if let detail {
                Text(detail)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(IIRYPalette.plum)
            }
        }
    }
}

struct IIRYBackdrop: View {
    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.94, green: 0.98, blue: 0.97),
                    Color(red: 0.91, green: 0.93, blue: 0.98),
                    Color(red: 0.99, green: 0.95, blue: 0.88)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            GridLines()
                .stroke(IIRYPalette.ink.opacity(0.055), lineWidth: 1)
                .ignoresSafeArea()
        }
        .ignoresSafeArea()
    }
}

struct GridLines: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        let step: CGFloat = 28
        var x = rect.minX
        while x <= rect.maxX {
            path.move(to: CGPoint(x: x, y: rect.minY))
            path.addLine(to: CGPoint(x: x, y: rect.maxY))
            x += step
        }
        var y = rect.minY
        while y <= rect.maxY {
            path.move(to: CGPoint(x: rect.minX, y: y))
            path.addLine(to: CGPoint(x: rect.maxX, y: y))
            y += step
        }
        return path
    }
}

struct IrinaLensArtwork: View {
    var body: some View {
        Canvas { context, size in
            let rect = CGRect(origin: .zero, size: size)
            context.fill(Path(rect), with: .linearGradient(
                Gradient(colors: [IIRYPalette.ink, IIRYPalette.plum, IIRYPalette.cyan]),
                startPoint: CGPoint(x: 0, y: 0),
                endPoint: CGPoint(x: size.width, y: size.height)
            ))

            let lens = CGRect(x: size.width * 0.52, y: size.height * 0.17, width: size.width * 0.32, height: size.width * 0.32)
            context.stroke(Path(ellipseIn: lens), with: .color(.white.opacity(0.86)), lineWidth: 5)
            context.stroke(Path(ellipseIn: lens.insetBy(dx: 10, dy: 10)), with: .color(IIRYPalette.amber.opacity(0.92)), lineWidth: 2)

            var handle = Path()
            handle.move(to: CGPoint(x: lens.midX + lens.width * 0.30, y: lens.midY + lens.height * 0.30))
            handle.addLine(to: CGPoint(x: size.width * 0.89, y: size.height * 0.82))
            context.stroke(handle, with: .color(.white.opacity(0.82)), lineWidth: 7)

            var profile = Path()
            profile.move(to: CGPoint(x: size.width * 0.22, y: size.height * 0.74))
            profile.addCurve(
                to: CGPoint(x: size.width * 0.42, y: size.height * 0.23),
                control1: CGPoint(x: size.width * 0.21, y: size.height * 0.42),
                control2: CGPoint(x: size.width * 0.29, y: size.height * 0.24)
            )
            profile.addCurve(
                to: CGPoint(x: size.width * 0.54, y: size.height * 0.63),
                control1: CGPoint(x: size.width * 0.54, y: size.height * 0.26),
                control2: CGPoint(x: size.width * 0.57, y: size.height * 0.49)
            )
            profile.addCurve(
                to: CGPoint(x: size.width * 0.22, y: size.height * 0.74),
                control1: CGPoint(x: size.width * 0.44, y: size.height * 0.78),
                control2: CGPoint(x: size.width * 0.32, y: size.height * 0.82)
            )
            context.fill(profile, with: .color(.white.opacity(0.18)))
            context.stroke(profile, with: .color(.white.opacity(0.72)), lineWidth: 2)

            var ear = Path()
            ear.move(to: CGPoint(x: size.width * 0.30, y: size.height * 0.34))
            ear.addLine(to: CGPoint(x: size.width * 0.18, y: size.height * 0.25))
            ear.addLine(to: CGPoint(x: size.width * 0.27, y: size.height * 0.44))
            context.fill(ear, with: .color(IIRYPalette.amber.opacity(0.34)))
            context.stroke(ear, with: .color(.white.opacity(0.65)), lineWidth: 1.5)

            for index in 0..<9 {
                let y = size.height * (0.18 + CGFloat(index) * 0.075)
                var signal = Path()
                signal.move(to: CGPoint(x: size.width * 0.08, y: y))
                signal.addLine(to: CGPoint(x: size.width * 0.92, y: y + (index.isMultiple(of: 2) ? 6 : -4)))
                context.stroke(signal, with: .color(.white.opacity(0.11)), lineWidth: 1)
            }
        }
        .overlay(alignment: .bottomLeading) {
            Text("Signals, not absolutes")
                .font(.system(size: 13, weight: .bold, design: .rounded))
                .foregroundStyle(.white.opacity(0.92))
                .padding(12)
        }
        .accessibilityLabel("Stylized signal lens artwork")
    }
}

struct IIRYPanelStyle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(14)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))
    }
}

struct IIRYPrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 15, weight: .bold, design: .rounded))
            .foregroundStyle(.white)
            .lineLimit(1)
            .minimumScaleFactor(0.84)
            .padding(.horizontal, 14)
            .frame(height: 44)
            .frame(maxWidth: .infinity)
            .background(IIRYPalette.ink, in: RoundedRectangle(cornerRadius: 8))
            .opacity(configuration.isPressed ? 0.82 : 1)
    }
}

struct IIRYSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 15, weight: .bold, design: .rounded))
            .foregroundStyle(IIRYPalette.ink)
            .lineLimit(1)
            .minimumScaleFactor(0.84)
            .padding(.horizontal, 14)
            .frame(height: 44)
            .frame(maxWidth: .infinity)
            .background(Color.white.opacity(configuration.isPressed ? 0.56 : 0.76), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))
    }
}

struct IIRYIconButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 17, weight: .bold))
            .foregroundStyle(IIRYPalette.ink)
            .background(Color.white.opacity(configuration.isPressed ? 0.52 : 0.74), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))
    }
}

enum IIRYPalette {
    static let ink = Color(red: 0.08, green: 0.13, blue: 0.18)
    static let plum = Color(red: 0.35, green: 0.18, blue: 0.43)
    static let cyan = Color(red: 0.18, green: 0.68, blue: 0.72)
    static let amber = Color(red: 0.95, green: 0.68, blue: 0.28)
    static let green = Color(red: 0.05, green: 0.48, blue: 0.32)
    static let rust = Color(red: 0.72, green: 0.22, blue: 0.16)
    static let panel = Color(red: 0.98, green: 0.99, blue: 0.98)
    static let line = Color.white.opacity(0.72)
}

struct ReceiptSnapshotView: View {
    let carrier: IIRYCarrier
    let image: UIImage
    let report: IIRYVerificationReport

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("IIRY")
                .font(.system(size: 34, weight: .black, design: .rounded))
            Text("Verification receipt")
                .font(.system(size: 17, weight: .bold, design: .rounded))
                .foregroundStyle(IIRYPalette.plum)
            Image(uiImage: image)
                .resizable()
                .scaledToFit()
                .frame(maxHeight: 420)
                .clipShape(RoundedRectangle(cornerRadius: 8))
            ForEach(report.checks) { check in
                CheckRow(check: check)
            }
            Text(carrier.suggestedFileName)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(IIRYPalette.ink.opacity(0.58))
        }
        .padding(22)
        .frame(width: 900, alignment: .leading)
        .background(IIRYPalette.panel)
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
