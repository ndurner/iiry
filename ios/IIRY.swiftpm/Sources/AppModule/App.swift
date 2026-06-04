import IIRYCore
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
    var serviceBaseURL = "https://iiry.ndurner.de"
    var requestText = (try? IIRYRequestText.make()) ?? "Is it really you?"
    var carrier: IIRYCarrier?
    var pendingSession: PresentationSession?
    var verificationReport: IIRYVerificationReport?
    var selectedImage: UIImage?
    var statusMessage: String?
    var errorMessage: String?
    var isBusy = false
    var showsImporter = false
    var shareItem: IIRYShareItem?

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
                    try await importC2PAJPEG(data, fileName: url.lastPathComponent)
                }
            } else {
                let prepared = try IIRYProofBuilder.prepare(imageData: data)
                carrier = prepared.carrier
                selectedImage = UIImage(data: data)
                verificationReport = try IIRYVerifier.verifyCarrier(prepared.carrier)
                pendingSession = nil
                statusMessage = "Image commitment prepared"
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func shareRequest() {
        do {
            refreshRequestText()
            let url = try writeTempText(requestText, fileName: "IIRY-request.txt")
            shareItem = IIRYShareItem(url: url)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func shareCarrier() {
        guard let carrier else {
            errorMessage = "No IIRY proof is ready."
            return
        }
        do {
            let data = try IIRYProofBuilder.carrierData(carrier)
            let url = try writeTempData(data, fileName: carrier.suggestedFileName)
            shareItem = IIRYShareItem(url: url)
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
            statusMessage = "Opening wallet"
            guard let walletURL = URL(string: session.openWalletURL) else {
                throw IIRYError.commandFailed("Invalid wallet URL from service")
            }
            await UIApplication.shared.open(walletURL)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func handle(url: URL) async {
        if url.isFileURL {
            await importFile(url)
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
                let signed = try await embedC2PAJPEG(carrier: updated)
                let url = try writeTempData(signed.jpegData, fileName: updated.suggestedFileName)
                self.statusMessage = "C2PA JPEG ready"
                self.shareItem = IIRYShareItem(url: url)
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

    private func importC2PAJPEG(_ data: Data, fileName: String) async throws {
        let inspection = try await inspectC2PAJPEG(imageData: data)
        let proof = try IIRYC2PAInspectionVerifier.extractProofBundle(fromDetailedJSON: inspection.detailedJSON)
        let report = try IIRYC2PAInspectionVerifier.verifyC2PAAsset(
            imageData: data,
            detailedJSON: inspection.detailedJSON
        )
        carrier = IIRYCarrier(
            suggestedFileName: fileName,
            imageB64URL: Base64URL.encode(data),
            proof: proof
        )
        selectedImage = UIImage(data: data)
        verificationReport = report
        pendingSession = nil
        statusMessage = "C2PA proof opened"
    }

    private func embedC2PAJPEG(carrier: IIRYCarrier) async throws -> C2PAEmbedResult {
        guard let url = URL(string: "\(serviceBaseURL)/api/c2pa/embed") else {
            throw IIRYError.commandFailed("Invalid service URL")
        }
        let imageData = try Base64URL.decode(carrier.imageB64URL)
        let manifestData = try IIRYC2PAManifestBuilder.manifestData(for: carrier, pretty: true)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "image_b64url": Base64URL.encode(imageData),
            "manifest_json_b64url": Base64URL.encode(manifestData),
            "suggested_file_name": carrier.suggestedFileName
        ])
        let (data, response) = try await URLSession.shared.data(for: request)
        try validateHTTP(response, data: data)
        let payload = try JSONDecoder().decode(C2PAEmbedPayload.self, from: data)
        return C2PAEmbedResult(
            jpegData: try Base64URL.decode(payload.jpegB64URL),
            detailedJSON: try Base64URL.decode(payload.c2patoolReportJSONB64URL),
            validationState: payload.validationState
        )
    }

    private func inspectC2PAJPEG(imageData: Data) async throws -> C2PAInspectionResult {
        guard let url = URL(string: "\(serviceBaseURL)/api/c2pa/inspect") else {
            throw IIRYError.commandFailed("Invalid service URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "image_b64url": Base64URL.encode(imageData)
        ])
        let (data, response) = try await URLSession.shared.data(for: request)
        try validateHTTP(response, data: data)
        let payload = try JSONDecoder().decode(C2PAInspectionPayload.self, from: data)
        return C2PAInspectionResult(
            detailedJSON: try Base64URL.decode(payload.c2patoolReportJSONB64URL),
            validationState: payload.validationState
        )
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
            let detail = String(data: data, encoding: .utf8) ?? "HTTP \(http.statusCode)"
            throw IIRYError.commandFailed(detail)
        }
    }

    private func writeTempText(_ text: String, fileName: String) throws -> URL {
        try writeTempData(Data(text.utf8), fileName: fileName)
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

struct C2PAEmbedPayload: Decodable {
    let jpegB64URL: String
    let c2patoolReportJSONB64URL: String
    let validationState: String?

    enum CodingKeys: String, CodingKey {
        case jpegB64URL = "jpeg_b64url"
        case c2patoolReportJSONB64URL = "c2patool_report_json_b64url"
        case validationState = "validation_state"
    }
}

struct C2PAInspectionPayload: Decodable {
    let c2patoolReportJSONB64URL: String
    let validationState: String?

    enum CodingKeys: String, CodingKey {
        case c2patoolReportJSONB64URL = "c2patool_report_json_b64url"
        case validationState = "validation_state"
    }
}

struct C2PAEmbedResult {
    let jpegData: Data
    let detailedJSON: Data
    let validationState: String?
}

struct C2PAInspectionResult {
    let detailedJSON: Data
    let validationState: String?
}

struct IIRYShareItem: Identifiable, Equatable {
    let id = UUID()
    let url: URL
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
            allowedContentTypes: [.jpeg, .iiryProof],
            allowsMultipleSelection: false
        ) { result in
            Task {
                if case .success(let urls) = result, let url = urls.first {
                    await model.importFile(url)
                }
            }
        }
        .sheet(item: $model.shareItem) { item in
            ShareSheet(activityItems: [item.url])
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

struct IntakePanel: View {
    @Bindable var model: IIRYAppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionTitle(title: "Prepare Image", detail: "JPEG or IIRY")
            Button {
                model.showsImporter = true
            } label: {
                Label("Choose JPEG", systemImage: "photo.badge.plus")
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
        VStack(alignment: .leading, spacing: 14) {
            SectionTitle(title: "Verification", detail: carrier.suggestedFileName)

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
                    Label("Open wallet", systemImage: "wallet.pass")
                }
                .buttonStyle(IIRYPrimaryButtonStyle())
                .disabled(model.isBusy)

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
        .modifier(IIRYPanelStyle())
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
