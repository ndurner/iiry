import IIRYCore
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers
import UIKit

@main
struct IIRYApp: App {
    @State private var model = IIRYAppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            IIRYRootView(model: model)
                .task {
                    await model.importSharedImageFromSharedContainerIfPresent()
                }
                .onOpenURL { url in
                    Task { await model.handle(url: url) }
                }
                .onChange(of: scenePhase) { _, phase in
                    if phase == .active {
                        Task { await model.importSharedImageFromSharedContainerIfPresent() }
                    }
                }
        }
    }
}

extension UTType {
    static let iiryC2PAFile = UTType(exportedAs: IIRYConstants.carrierUTType)
}

@Observable
@MainActor
final class IIRYAppModel {
    static let defaultServiceBaseURL = "https://iiry.ndurner.de"
    private static let serviceBaseURLKey = "iiry.serviceBaseURL"
    private static let appGroupIdentifier = "group.de.ndurner.iiry"
    private static let handoffImageName = "shared-image.bin"
    private static let handoffMetadataName = "shared-image.json"

    var serviceBaseURL: String
    var requestText: String
    var draft: IIRYCommitmentDraft?
    var pendingSession: PresentationSession?
    var verificationReport: IIRYVerificationReport?
    var selectedImage: UIImage?
    var statusMessage: String?
    var errorMessage: String?
    var isBusy = false
    var showsImporter = false
    var showsSettings = false
    var shareItem: IIRYShareItem?
    var signedCommitmentURL: URL?
    var imagePreparationSource: ImagePreparationSource?
    var commitmentDisplayMode: CommitmentDisplayMode = .draft

    init() {
        self.serviceBaseURL = UserDefaults.standard.string(forKey: Self.serviceBaseURLKey) ?? Self.defaultServiceBaseURL
        self.requestText = (try? IIRYRequestText.make()) ?? "Is it really you?"
    }

    var hasPreparedProof: Bool {
        draft != nil
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
                if data.starts(with: [0xff, 0xd8]) {
                    try importC2PAJPEG(data, fileName: url.lastPathComponent)
                } else {
                    throw IIRYError.invalidCarrier("Detached .iiry carriers are no longer supported. Open the signed C2PA JPEG instead.")
                }
            } else {
                try prepareImage(data, source: .file)
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
            try prepareImage(data, source: .photos)
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

    func shareCommitment() {
        guard let signedCommitmentURL else {
            errorMessage = "No signed C2PA JPEG is ready. Complete the wallet commitment first."
            return
        }
        shareItem = IIRYShareItem(activityItems: [IIRYCommitmentActivityItem(fileURL: signedCommitmentURL)])
    }

    func startWalletFlow() async {
        guard let draft else {
            errorMessage = "Import a JPEG first."
            return
        }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let session = try await createPresentationSession(for: draft)
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

    func importSharedImageFromSharedContainerIfPresent() async {
        if await importSharedImageFromSharedContainer(showMissingError: false) {
            return
        }
        await importSharedImageFromGeneralPasteboardIfPresent()
    }

    func importStagedSharedImage() async {
        if await importSharedImageFromSharedContainer(showMissingError: true) {
            return
        }
        await importSharedImageFromGeneralPasteboardIfPresent(showMissingError: true)
    }

    private func importSharedImageFromGeneralPasteboardIfPresent(showMissingError: Bool = false) async {
        if let stagedImage = UIPasteboard.general.data(forPasteboardType: "de.ndurner.iiry.share-image"),
           !stagedImage.isEmpty {
            isBusy = true
            errorMessage = nil
            defer { isBusy = false }
            do {
                try prepareImage(stagedImage, source: .shared)
                clearGeneralShareHandoff()
                statusMessage = "Ready to commit"
            } catch {
                errorMessage = error.localizedDescription
            }
            return
        }

        guard let data = UIPasteboard.general.data(forPasteboardType: "de.ndurner.iiry.share-url"),
              let rawURL = String(data: data, encoding: .utf8),
              let url = URL(string: rawURL),
              url.scheme == "iiry",
              url.host == "share-image" else {
            if showMissingError {
                errorMessage = "No staged IIRY image was found. Share the screenshot to IIRY again."
            }
            return
        }
        await importSharedImage(url)
    }

    private func importSharedImageFromSharedContainer(showMissingError: Bool) async -> Bool {
        guard let directory = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroupIdentifier) else {
            if showMissingError {
                errorMessage = "IIRY shared storage is unavailable. Reinstall the app with the app-group entitlement."
            }
            return false
        }

        let imageURL = directory.appendingPathComponent(Self.handoffImageName)
        guard FileManager.default.fileExists(atPath: imageURL.path) else {
            if showMissingError {
                errorMessage = "No staged IIRY image was found. Share the screenshot to IIRY again."
            }
            return false
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let data = try Data(contentsOf: imageURL)
            try prepareImage(data, source: .shared)
            clearSharedImageHandoff(in: directory)
            statusMessage = "Ready to commit"
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func fetchWalletResponse(state: String, token: String) async {
        guard let draft else {
            errorMessage = "No local proof is waiting for this wallet response."
            return
        }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let response = try await walletResponse(state: state, token: token)
            let updated = try IIRYProofBuilder.attachPresentation(
                draft: draft,
                decodedResponseJSON: response.decodedResponseJSON,
                walletVerification: response.verification
            )
            self.draft = updated
            self.selectedImage = UIImage(data: try Base64URL.decode(updated.imageB64URL))
            self.verificationReport = nil
            self.signedCommitmentURL = nil
            self.commitmentDisplayMode = .createdCommitment
            self.statusMessage = "Wallet response received; signing C2PA JPEG"
            do {
                let signed = try IIRYC2PAAssetProcessor.signJPEG(draft: updated)
                self.verificationReport = try IIRYC2PAAssetProcessor.verifyJPEG(signed.jpegData)
                self.signedCommitmentURL = try writeTempData(
                    signed.jpegData,
                    fileName: IIRYFileNames.c2paTransportFileName(from: updated.suggestedFileName)
                )
                self.statusMessage = "Commitment ready to share"
            } catch {
                self.errorMessage = "C2PA signing unavailable: \(error.localizedDescription)"
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func saveReceiptToPhotos() {
        guard let draft, let image = selectedImage, let report = verificationReport else {
            errorMessage = "No verification receipt is ready."
            return
        }
        let renderer = ImageRenderer(content: ReceiptSnapshotView(draft: draft, image: image, report: report))
        renderer.scale = UIScreen.main.scale
        guard let output = renderer.uiImage else {
            errorMessage = "Could not render receipt."
            return
        }
        UIImageWriteToSavedPhotosAlbum(output, nil, nil, nil)
        statusMessage = "Receipt saved"
    }

    private func createPresentationSession(for draft: IIRYCommitmentDraft) async throws -> PresentationSession {
        guard let url = URL(string: "\(serviceBaseURL)/api/presentations") else {
            throw IIRYError.commandFailed("Invalid service URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "nonce": draft.proof.openID4VP.nonce
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
                guard let data = UIPasteboard.general.data(forPasteboardType: "de.ndurner.iiry.share-image"), !data.isEmpty else {
                    throw IIRYError.invalidCarrier("Shared image handoff expired")
                }
                try prepareImage(data, source: .shared)
                clearGeneralShareHandoff()
                return
            }
            guard let data = pasteboard.data(forPasteboardType: type)
                ?? pasteboard.data(forPasteboardType: UTType.jpeg.identifier)
                ?? pasteboard.data(forPasteboardType: UTType.png.identifier)
                ?? pasteboard.data(forPasteboardType: UTType.data.identifier) else {
                throw IIRYError.invalidCarrier("Shared image handoff did not contain image data")
            }
            try prepareImage(data, source: .shared)
            pasteboard.items = []
            clearGeneralShareHandoff()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func importC2PAJPEG(_ data: Data, fileName: String) throws {
        let report = try IIRYC2PAAssetProcessor.verifyJPEG(data)
        let importedDraft = try IIRYC2PAAssetProcessor.draft(fromJPEGData: data, suggestedFileName: fileName)
        let visualData = try Base64URL.decode(importedDraft.imageB64URL)
        draft = importedDraft
        signedCommitmentURL = nil
        selectedImage = UIImage(data: visualData)
        verificationReport = report
        pendingSession = nil
        imagePreparationSource = .file
        commitmentDisplayMode = .receivedVerification
        statusMessage = "C2PA proof opened"
    }

    private func prepareImage(_ data: Data, source: ImagePreparationSource) throws {
        let jpegData = try normalizedJPEGData(from: data)
        let prepared = try IIRYProofBuilder.prepare(imageData: jpegData)
        draft = prepared.draft
        signedCommitmentURL = nil
        selectedImage = UIImage(data: jpegData)
        verificationReport = nil
        pendingSession = nil
        imagePreparationSource = source
        commitmentDisplayMode = .draft
        statusMessage = source == .shared ? "Ready to commit" : (isJPEG(data) ? "Image commitment prepared" : "Image converted to JPEG and prepared")
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

    private func clearGeneralShareHandoff() {
        UIPasteboard.general.setData(Data(), forPasteboardType: "de.ndurner.iiry.share-url")
        UIPasteboard.general.setData(Data(), forPasteboardType: "de.ndurner.iiry.share-image")
        UIPasteboard.general.setData(Data(), forPasteboardType: "de.ndurner.iiry.share-image-type")
    }

    private func clearSharedImageHandoff(in directory: URL) {
        for fileName in [Self.handoffImageName, Self.handoffMetadataName] {
            let url = directory.appendingPathComponent(fileName)
            try? FileManager.default.removeItem(at: url)
        }
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

enum ImagePreparationSource {
    case shared
    case photos
    case file
}

enum CommitmentDisplayMode {
    case draft
    case createdCommitment
    case receivedVerification
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
            if let draft = model.draft, let image = model.selectedImage {
                ActiveProofView(model: model, draft: draft, image: image)
            } else {
                ScrollView(showsIndicators: false) {
                    VStack(alignment: .leading, spacing: 18) {
                        HeroPanel(model: model)
                        IntakePanel(model: model)
                            .padding(.top, 18)
                        StatusPanel(model: model)
                    }
                    .padding(.horizontal, 18)
                    .padding(.top, 18)
                    .padding(.bottom, 34)
                }
            }
        }
        .fileImporter(
            isPresented: $model.showsImporter,
            allowedContentTypes: [.image, .iiryC2PAFile],
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

struct ActiveProofView: View {
    @Bindable var model: IIRYAppModel
    let draft: IIRYCommitmentDraft
    let image: UIImage
    @State private var showsTechnicalChecks = false
    @State private var showsImageInspector = false

    var body: some View {
        GeometryReader { geometry in
            let hasReport = model.verificationReport != nil
            let hasProof = model.verificationReport?.overallPassed == true
            let isReceivedVerification = model.commitmentDisplayMode == .receivedVerification

            VStack(alignment: .leading, spacing: 12) {
                CompactHeader(
                    title: hasReport ? "Verification" : "Commitment",
                    detail: hasProof ? (isReceivedVerification ? "Received commitment" : "Ready to share") : (hasReport ? "Verification failed" : "Review the image")
                ) {
                    model.showsSettings = true
                }

                VStack(alignment: .leading, spacing: 10) {
                    HStack(alignment: .center, spacing: 10) {
                        Image(systemName: hasProof ? "checkmark.seal.fill" : (hasReport ? "xmark.seal.fill" : "scope"))
                            .foregroundStyle(hasProof ? IIRYPalette.green : (hasReport ? IIRYPalette.rust : IIRYPalette.plum))
                            .frame(width: 24)
                        Text(statusHeadline(hasReport: hasReport, hasProof: hasProof, mode: model.commitmentDisplayMode))
                            .font(.system(size: 15, weight: .bold, design: .rounded))
                            .foregroundStyle(IIRYPalette.ink)
                            .lineLimit(2)
                            .minimumScaleFactor(0.82)
                    }

                    if hasReport {
                        IdentityBanner(name: draft.proof.committedPersonNameDisclosureComplete ? draft.proof.committedPersonName : nil)
                    }

                    Image(uiImage: image)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: .infinity)
                        .frame(maxHeight: hasReport ? geometry.size.height * 0.44 : geometry.size.height * 0.58)
                        .background(Color.black.opacity(0.04), in: RoundedRectangle(cornerRadius: 8))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))
                        .overlay(alignment: .bottomTrailing) {
                            Label("Inspect", systemImage: "plus.magnifyingglass")
                                .font(.system(size: 12, weight: .bold, design: .rounded))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 7)
                                .background(IIRYPalette.ink.opacity(0.82), in: Capsule())
                                .padding(10)
                        }
                        .contentShape(RoundedRectangle(cornerRadius: 8))
                        .onTapGesture {
                            showsImageInspector = true
                        }
                        .accessibilityAddTraits(.isButton)
                        .accessibilityLabel("Open screenshot full screen")

                    if let report = model.verificationReport {
                        Button {
                            withAnimation(.snappy) {
                                showsTechnicalChecks.toggle()
                            }
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: showsTechnicalChecks ? "chevron.down" : "chevron.right")
                                    .font(.system(size: 12, weight: .bold))
                                Text("Technical verification details")
                                Spacer(minLength: 0)
                            }
                        }
                        .buttonStyle(IIRYDisclosureButtonStyle())

                        if showsTechnicalChecks {
                            ScrollView(showsIndicators: false) {
                                VStack(spacing: 8) {
                                    ForEach(report.checks) { check in
                                        CheckRow(check: check)
                                    }
                                }
                            }
                            .frame(maxHeight: geometry.size.height * 0.20)
                        }
                    }

                    ActionRow(model: model, hasProof: hasProof)
                }
                .modifier(IIRYPanelStyle())

                CompactStatusPanel(model: model)
            }
            .padding(.horizontal, 18)
            .padding(.top, 18)
            .padding(.bottom, 18)
            .frame(width: geometry.size.width, height: geometry.size.height, alignment: .top)
        }
        .fullScreenCover(isPresented: $showsImageInspector) {
            ImageInspectorView(image: image, title: "Committed image")
        }
    }

    private func statusHeadline(hasReport: Bool, hasProof: Bool, mode: CommitmentDisplayMode) -> String {
        guard hasReport else {
            return "Confirm the challenge is visible in the image."
        }
        guard hasProof else {
            return "This commitment does not meet the current verification profile."
        }
        switch mode {
        case .receivedVerification:
            return "Wallet-backed commitment confirmed."
        case .createdCommitment:
            return "Wallet-backed commitment is ready."
        case .draft:
            return "Wallet-backed commitment is attached."
        }
    }
}

struct IdentityBanner: View {
    let name: String?

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: name == nil ? "person.crop.circle.badge.exclamationmark" : "person.crop.circle.badge.checkmark")
                .foregroundStyle(name == nil ? IIRYPalette.rust : IIRYPalette.green)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                Text(name == nil ? "Wallet holder name not disclosed" : "Committed by")
                    .font(.system(size: 12, weight: .bold, design: .rounded))
                    .foregroundStyle(IIRYPalette.ink.opacity(0.58))
                    .textCase(.uppercase)
                Text(name ?? "No given_name/family_name in the presentation")
                    .font(.system(size: 18, weight: .black, design: .rounded))
                    .foregroundStyle(IIRYPalette.ink)
                    .lineLimit(1)
                    .minimumScaleFactor(0.78)
            }

            Spacer(minLength: 0)
        }
        .padding(12)
        .background(Color.white.opacity(0.66), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))
    }
}

struct CompactHeader: View {
    let title: String
    let detail: String
    let onSettings: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("IIRY")
                    .font(.system(size: 22, weight: .black, design: .rounded))
                    .foregroundStyle(IIRYPalette.ink)
                Text(title)
                    .font(.system(size: 30, weight: .black, design: .rounded))
                    .foregroundStyle(IIRYPalette.ink)
                    .lineLimit(1)
                    .minimumScaleFactor(0.78)
                Text(detail)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .foregroundStyle(IIRYPalette.plum)
                    .lineLimit(1)
            }
            Spacer(minLength: 8)
            Button {
                onSettings()
            } label: {
                Image(systemName: "gearshape")
                    .frame(width: 44, height: 44)
            }
            .buttonStyle(IIRYIconButtonStyle())
            .accessibilityLabel("Settings")
        }
    }
}

struct ActionRow: View {
    @Bindable var model: IIRYAppModel
    let hasProof: Bool

    var body: some View {
        HStack(spacing: 10) {
            if hasProof {
                if model.commitmentDisplayMode != .receivedVerification {
                    Button {
                        model.shareCommitment()
                    } label: {
                        Label("Share commitment", systemImage: "square.and.arrow.up")
                    }
                    .buttonStyle(IIRYPrimaryButtonStyle())
                }

                if model.commitmentDisplayMode == .receivedVerification {
                    Button {
                        model.saveReceiptToPhotos()
                    } label: {
                        Label("Save receipt", systemImage: "square.and.arrow.down")
                    }
                    .buttonStyle(IIRYPrimaryButtonStyle())
                    .accessibilityLabel("Save receipt")
                } else {
                    Button {
                        model.saveReceiptToPhotos()
                    } label: {
                        Image(systemName: "square.and.arrow.down")
                            .frame(width: 44, height: 44)
                    }
                    .buttonStyle(IIRYIconButtonStyle())
                    .accessibilityLabel("Save receipt")
                }
            } else {
                Button {
                    Task { await model.startWalletFlow() }
                } label: {
                    Label("Commit to it", systemImage: "wallet.pass")
                }
                .buttonStyle(IIRYPrimaryButtonStyle())
                .disabled(model.isBusy)
            }
        }
    }
}

struct CompactStatusPanel: View {
    @Bindable var model: IIRYAppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            if model.isBusy {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Working")
                }
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
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(Color.white.opacity(0.68), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))
    }
}

struct ImageInspectorView: View {
    let image: UIImage
    let title: String
    @Environment(\.dismiss) private var dismiss
    @State private var showsChrome = true
    @State private var chromeHideTask: Task<Void, Never>?

    var body: some View {
        ZStack {
            Color(red: 0.03, green: 0.05, blue: 0.08)
                .ignoresSafeArea()

            ZoomableImageView(
                image: image,
                onSingleTap: {
                    withAnimation(.easeInOut(duration: 0.18)) {
                        showsChrome.toggle()
                    }
                    if showsChrome {
                        scheduleChromeHide()
                    } else {
                        chromeHideTask?.cancel()
                    }
                },
                onDoubleTap: {
                    withAnimation(.easeInOut(duration: 0.18)) {
                        showsChrome = false
                    }
                    chromeHideTask?.cancel()
                }
            )
                .ignoresSafeArea()

            if showsChrome {
                VStack(spacing: 0) {
                    HStack(alignment: .center, spacing: 12) {
                        Text(title)
                            .font(.system(size: 21, weight: .black, design: .rounded))
                            .foregroundStyle(.white)
                            .lineLimit(1)
                            .minimumScaleFactor(0.78)

                        Spacer(minLength: 8)

                        Button {
                            dismiss()
                        } label: {
                            Image(systemName: "xmark")
                                .font(.system(size: 15, weight: .black))
                                .foregroundStyle(.white)
                                .frame(width: 40, height: 40)
                                .background(Color.black.opacity(0.44), in: Circle())
                                .overlay(Circle().stroke(.white.opacity(0.24), lineWidth: 1))
                        }
                        .accessibilityLabel("Close image inspector")
                    }
                    .padding(.horizontal, 18)
                    .padding(.top, 8)
                    .padding(.bottom, 8)
                    .background(
                        LinearGradient(
                            colors: [.black.opacity(0.58), .black.opacity(0.18)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )

                    Spacer()

                    HStack(spacing: 8) {
                        Image(systemName: "hand.draw")
                        Text("Pinch to zoom. Double-tap to inspect. Tap once to hide controls.")
                            .lineLimit(1)
                            .minimumScaleFactor(0.75)
                    }
                    .font(.system(size: 12, weight: .bold, design: .rounded))
                    .foregroundStyle(.white.opacity(0.88))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 9)
                    .background(Color.black.opacity(0.58), in: Capsule())
                    .overlay(Capsule().stroke(.white.opacity(0.16), lineWidth: 1))
                    .padding(.horizontal, 16)
                    .padding(.bottom, 16)
                }
                .transition(.opacity)
            }
        }
        .task {
            scheduleChromeHide()
        }
        .onDisappear {
            chromeHideTask?.cancel()
        }
    }

    private func scheduleChromeHide() {
        chromeHideTask?.cancel()
        chromeHideTask = Task { @MainActor in
            try? await Task.sleep(for: .seconds(2.4))
            guard !Task.isCancelled else {
                return
            }
            withAnimation(.easeInOut(duration: 0.22)) {
                showsChrome = false
            }
        }
    }
}

struct ZoomableImageView: UIViewRepresentable {
    let image: UIImage
    let onSingleTap: () -> Void
    let onDoubleTap: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onSingleTap: onSingleTap, onDoubleTap: onDoubleTap)
    }

    func makeUIView(context: Context) -> UIScrollView {
        let scrollView = UIScrollView()
        scrollView.delegate = context.coordinator
        scrollView.backgroundColor = .clear
        scrollView.minimumZoomScale = 1
        scrollView.maximumZoomScale = 7
        scrollView.bouncesZoom = true
        scrollView.showsHorizontalScrollIndicator = false
        scrollView.showsVerticalScrollIndicator = false
        scrollView.decelerationRate = .fast
        scrollView.contentInsetAdjustmentBehavior = .never

        let imageView = UIImageView(image: image)
        imageView.contentMode = .scaleAspectFit
        imageView.isUserInteractionEnabled = true
        imageView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.addSubview(imageView)

        NSLayoutConstraint.activate([
            imageView.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor),
            imageView.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor),
            imageView.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor),
            imageView.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor),
            imageView.widthAnchor.constraint(equalTo: scrollView.frameLayoutGuide.widthAnchor),
            imageView.heightAnchor.constraint(equalTo: scrollView.frameLayoutGuide.heightAnchor)
        ])

        let doubleTap = UITapGestureRecognizer(target: context.coordinator, action: #selector(Coordinator.handleDoubleTap(_:)))
        doubleTap.numberOfTapsRequired = 2
        scrollView.addGestureRecognizer(doubleTap)

        let singleTap = UITapGestureRecognizer(target: context.coordinator, action: #selector(Coordinator.handleSingleTap(_:)))
        singleTap.numberOfTapsRequired = 1
        singleTap.require(toFail: doubleTap)
        scrollView.addGestureRecognizer(singleTap)

        context.coordinator.imageView = imageView
        context.coordinator.scrollView = scrollView
        return scrollView
    }

    func updateUIView(_ scrollView: UIScrollView, context: Context) {
        context.coordinator.imageView?.image = image
        context.coordinator.onSingleTap = onSingleTap
        context.coordinator.onDoubleTap = onDoubleTap
    }

    final class Coordinator: NSObject, UIScrollViewDelegate {
        weak var imageView: UIImageView?
        weak var scrollView: UIScrollView?
        var onSingleTap: () -> Void
        var onDoubleTap: () -> Void

        init(onSingleTap: @escaping () -> Void, onDoubleTap: @escaping () -> Void) {
            self.onSingleTap = onSingleTap
            self.onDoubleTap = onDoubleTap
        }

        func viewForZooming(in scrollView: UIScrollView) -> UIView? {
            imageView
        }

        @objc
        func handleSingleTap(_ recognizer: UITapGestureRecognizer) {
            onSingleTap()
        }

        @objc
        func handleDoubleTap(_ recognizer: UITapGestureRecognizer) {
            guard let scrollView else {
                return
            }
            onDoubleTap()
            if scrollView.zoomScale > scrollView.minimumZoomScale + 0.1 {
                scrollView.setZoomScale(scrollView.minimumZoomScale, animated: true)
            } else {
                let point = recognizer.location(in: imageView)
                let scale = min(3, scrollView.maximumZoomScale)
                let size = CGSize(width: scrollView.bounds.width / scale, height: scrollView.bounds.height / scale)
                let origin = CGPoint(x: point.x - size.width / 2, y: point.y - size.height / 2)
                scrollView.zoom(to: CGRect(origin: origin, size: size), animated: true)
            }
        }
    }
}

struct HeroPanel: View {
    @Bindable var model: IIRYAppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            ZStack(alignment: .topTrailing) {
                IIRYHeroImage()
                    .frame(height: 156)
                    .clipShape(RoundedRectangle(cornerRadius: 8))

                ExperimentalBadge()
                    .padding(.trailing, 14)
                    .padding(.top, 14)
            }

            VStack(alignment: .leading, spacing: 7) {
                HStack(alignment: .top, spacing: 12) {
                    Text("IIRY")
                        .font(.system(size: 46, weight: .black, design: .rounded))
                        .foregroundStyle(IIRYPalette.ink)

                    Spacer(minLength: 8)

                    Button {
                        model.showsSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                            .frame(width: 44, height: 44)
                    }
                    .buttonStyle(IIRYIconButtonStyle())
                    .accessibilityLabel("Settings")
                }

                Text("Is It Really You?")
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                    .foregroundStyle(IIRYPalette.plum)

                Text("Content Credentials, backed by EUDIW.\nAsk, send and verify Commitments to image content.")
                    .font(.system(size: 15, weight: .medium, design: .rounded))
                    .foregroundStyle(IIRYPalette.ink.opacity(0.70))
                    .lineSpacing(2)
            }

            ChallengeFlowSummary(requestText: model.requestText)

            HStack(spacing: 10) {
                Button {
                    model.shareRequest()
                } label: {
                    Label("Send challenge", systemImage: "paperplane")
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
            }
        }
        .padding(14)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.line, lineWidth: 1))
    }
}

struct IIRYHeroImage: View {
    var body: some View {
        Image("IIRYHero")
            .resizable()
            .scaledToFill()
            .accessibilityLabel("IIRY assistant checking a message challenge")
    }
}

struct ExperimentalBadge: View {
    var body: some View {
        Text("Experimental")
            .font(.system(size: 8, weight: .bold, design: .rounded))
            .foregroundStyle(IIRYPalette.rust)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .overlay(Capsule().stroke(IIRYPalette.rust.opacity(0.82), lineWidth: 1))
            .accessibilityLabel("Experimental hackathon project")
    }
}

struct ChallengeFlowSummary: View {
    let requestText: String

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 12) {
                FlowStep(icon: "message", title: "Challenge")
                ConnectorLine()
                FlowStep(icon: "wallet.pass", title: "Wallet")
                ConnectorLine()
                FlowStep(icon: "photo", title: "Commitment")
            }

            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(IIRYPalette.ink.opacity(0.74))
                    .frame(width: 28, height: 28)
                    .background(Color.white.opacity(0.72), in: RoundedRectangle(cornerRadius: 6))
                    .accessibilityHidden(true)

                Text(requestText)
                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                    .foregroundStyle(IIRYPalette.ink.opacity(0.78))
                    .lineLimit(3)
                    .minimumScaleFactor(0.82)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(12)
            .background(IIRYPalette.panel.opacity(0.82), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.ink.opacity(0.08), lineWidth: 1))
        }
        .padding(12)
        .background(
            LinearGradient(
                colors: [
                    Color.white.opacity(0.74),
                    IIRYPalette.cyan.opacity(0.08)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 8)
        )
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.ink.opacity(0.08), lineWidth: 1))
    }
}

struct FlowStep: View {
    let icon: String
    let title: String

    var body: some View {
        VStack(spacing: 7) {
            Image(systemName: icon)
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(IIRYPalette.ink)
                .frame(width: 34, height: 34)
                .background(Color.white.opacity(0.82), in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(IIRYPalette.ink.opacity(0.08), lineWidth: 1))
                .accessibilityHidden(true)

            Text(title)
                .font(.system(size: 11, weight: .semibold, design: .rounded))
                .foregroundStyle(IIRYPalette.ink.opacity(0.68))
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(width: 64)
    }
}

struct ConnectorLine: View {
    var body: some View {
        Rectangle()
            .fill(IIRYPalette.ink.opacity(0.16))
            .frame(height: 1)
            .frame(maxWidth: .infinity)
            .padding(.bottom, 18)
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
            SectionTitle(title: "Commit to image", detail: "Photos or file")
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
                Task { await model.importStagedSharedImage() }
            } label: {
                Label("Continue shared image", systemImage: "arrow.down.doc")
            }
            .buttonStyle(IIRYSecondaryButtonStyle())
            .disabled(model.isBusy)

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
    let draft: IIRYCommitmentDraft
    let image: UIImage

    var body: some View {
        let hasProof = model.verificationReport?.overallPassed == true

        VStack(alignment: .leading, spacing: 14) {
            SectionTitle(title: model.verificationReport == nil ? "Commitment" : (hasProof ? "Verification" : "Verification failed"), detail: draft.suggestedFileName)

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
                        model.shareCommitment()
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

struct IIRYDisclosureButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .bold, design: .rounded))
            .foregroundStyle(IIRYPalette.ink.opacity(0.68))
            .padding(.horizontal, 10)
            .frame(height: 36)
            .background(Color.white.opacity(configuration.isPressed ? 0.42 : 0.58), in: RoundedRectangle(cornerRadius: 8))
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
    let draft: IIRYCommitmentDraft
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
            Text(draft.suggestedFileName)
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

final class IIRYCommitmentActivityItem: NSObject, UIActivityItemSource {
    let fileURL: URL

    init(fileURL: URL) {
        self.fileURL = fileURL
        super.init()
    }

    func activityViewControllerPlaceholderItem(_ activityViewController: UIActivityViewController) -> Any {
        fileURL
    }

    func activityViewController(
        _ activityViewController: UIActivityViewController,
        itemForActivityType activityType: UIActivity.ActivityType?
    ) -> Any? {
        fileURL
    }

    func activityViewController(
        _ activityViewController: UIActivityViewController,
        dataTypeIdentifierForActivityType activityType: UIActivity.ActivityType?
    ) -> String {
        IIRYConstants.carrierUTType
    }

    func activityViewController(
        _ activityViewController: UIActivityViewController,
        subjectForActivityType activityType: UIActivity.ActivityType?
    ) -> String {
        fileURL.lastPathComponent
    }
}
