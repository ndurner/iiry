import UIKit
import UniformTypeIdentifiers

final class ShareViewController: UIViewController {
    private static let appGroupIdentifier = "group.de.ndurner.iiry"
    private static let handoffImageName = "shared-image.bin"
    private static let handoffMetadataName = "shared-image.json"

    private let cardView = UIView()
    private let iconView = UIView()
    private let iconLabel = UILabel()
    private let titleLabel = UILabel()
    private let statusLabel = UILabel()
    private let instructionLabel = UILabel()
    private let imageView = UIImageView()
    private let commitButton = UIButton(type: .system)
    private let cancelButton = UIButton(type: .system)
    private var imageData: Data?
    private var imageType = UTType.data.identifier
    private var isPreparedForApp = false

    override func viewDidLoad() {
        super.viewDidLoad()
        preferredContentSize = CGSize(width: 360, height: 360)
        setupUI()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        loadSharedImage()
    }

    private func setupUI() {
        view.backgroundColor = UIColor(red: 0.94, green: 0.98, blue: 0.97, alpha: 1)

        cardView.translatesAutoresizingMaskIntoConstraints = false
        cardView.backgroundColor = UIColor(white: 1, alpha: 0.82)
        cardView.layer.cornerRadius = 18
        cardView.layer.borderColor = UIColor.white.withAlphaComponent(0.86).cgColor
        cardView.layer.borderWidth = 1

        iconView.translatesAutoresizingMaskIntoConstraints = false
        iconView.backgroundColor = UIColor(red: 0.08, green: 0.13, blue: 0.18, alpha: 1)
        iconView.layer.cornerRadius = 8

        iconLabel.translatesAutoresizingMaskIntoConstraints = false
        iconLabel.text = "IIRY"
        iconLabel.textColor = .white
        iconLabel.font = .systemFont(ofSize: 10, weight: .black)
        iconLabel.textAlignment = .center

        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.text = "Commit in IIRY"
        titleLabel.font = .systemFont(ofSize: 26, weight: .black)
        titleLabel.textColor = UIColor(red: 0.08, green: 0.13, blue: 0.18, alpha: 1)

        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .systemFont(ofSize: 15, weight: .semibold)
        statusLabel.textColor = UIColor(red: 0.35, green: 0.18, blue: 0.43, alpha: 1)
        statusLabel.numberOfLines = 0
        statusLabel.text = "Reading the shared image..."

        instructionLabel.translatesAutoresizingMaskIntoConstraints = false
        instructionLabel.font = .systemFont(ofSize: 13, weight: .medium)
        instructionLabel.textColor = UIColor(red: 0.08, green: 0.13, blue: 0.18, alpha: 0.62)
        instructionLabel.numberOfLines = 0
        instructionLabel.text = "Review the image, then hand it to IIRY for the wallet commitment."

        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.contentMode = .scaleAspectFit
        imageView.backgroundColor = UIColor(red: 0.91, green: 0.93, blue: 0.98, alpha: 0.70)
        imageView.layer.cornerRadius = 14
        imageView.layer.borderColor = UIColor.white.withAlphaComponent(0.86).cgColor
        imageView.layer.borderWidth = 1
        imageView.clipsToBounds = true

        commitButton.translatesAutoresizingMaskIntoConstraints = false
        commitButton.setTitle("Commit in IIRY", for: .normal)
        commitButton.titleLabel?.font = .systemFont(ofSize: 17, weight: .bold)
        commitButton.setTitleColor(.white, for: .normal)
        commitButton.setTitleColor(UIColor.white.withAlphaComponent(0.54), for: .disabled)
        commitButton.backgroundColor = UIColor(red: 0.08, green: 0.13, blue: 0.18, alpha: 1)
        commitButton.layer.cornerRadius = 12
        commitButton.isEnabled = false
        commitButton.addTarget(self, action: #selector(commitImage), for: .touchUpInside)

        cancelButton.translatesAutoresizingMaskIntoConstraints = false
        cancelButton.setTitle("Cancel", for: .normal)
        cancelButton.titleLabel?.font = .systemFont(ofSize: 16, weight: .semibold)
        cancelButton.setTitleColor(UIColor(red: 0.35, green: 0.18, blue: 0.43, alpha: 1), for: .normal)
        cancelButton.addTarget(self, action: #selector(cancel), for: .touchUpInside)

        let buttons = UIStackView(arrangedSubviews: [cancelButton, commitButton])
        buttons.translatesAutoresizingMaskIntoConstraints = false
        buttons.axis = .horizontal
        buttons.distribution = .fillEqually
        buttons.spacing = 12

        let header = UIStackView(arrangedSubviews: [iconView, titleLabel])
        header.translatesAutoresizingMaskIntoConstraints = false
        header.axis = .horizontal
        header.alignment = .center
        header.spacing = 10

        iconView.addSubview(iconLabel)
        view.addSubview(cardView)
        cardView.addSubview(header)
        cardView.addSubview(statusLabel)
        cardView.addSubview(instructionLabel)
        cardView.addSubview(imageView)
        cardView.addSubview(buttons)

        NSLayoutConstraint.activate([
            cardView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 14),
            cardView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 14),
            cardView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -14),
            cardView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -14),

            iconView.widthAnchor.constraint(equalToConstant: 34),
            iconView.heightAnchor.constraint(equalToConstant: 34),
            iconLabel.centerXAnchor.constraint(equalTo: iconView.centerXAnchor),
            iconLabel.centerYAnchor.constraint(equalTo: iconView.centerYAnchor),

            header.topAnchor.constraint(equalTo: cardView.topAnchor, constant: 16),
            header.leadingAnchor.constraint(equalTo: cardView.leadingAnchor, constant: 16),
            header.trailingAnchor.constraint(equalTo: cardView.trailingAnchor, constant: -16),

            statusLabel.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 10),
            statusLabel.leadingAnchor.constraint(equalTo: cardView.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(equalTo: cardView.trailingAnchor, constant: -16),

            instructionLabel.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 4),
            instructionLabel.leadingAnchor.constraint(equalTo: cardView.leadingAnchor, constant: 16),
            instructionLabel.trailingAnchor.constraint(equalTo: cardView.trailingAnchor, constant: -16),

            imageView.topAnchor.constraint(equalTo: instructionLabel.bottomAnchor, constant: 14),
            imageView.leadingAnchor.constraint(equalTo: cardView.leadingAnchor, constant: 16),
            imageView.trailingAnchor.constraint(equalTo: cardView.trailingAnchor, constant: -16),
            imageView.bottomAnchor.constraint(equalTo: buttons.topAnchor, constant: -14),

            buttons.leadingAnchor.constraint(equalTo: cardView.leadingAnchor, constant: 16),
            buttons.trailingAnchor.constraint(equalTo: cardView.trailingAnchor, constant: -16),
            buttons.bottomAnchor.constraint(equalTo: cardView.bottomAnchor, constant: -16),
            buttons.heightAnchor.constraint(equalToConstant: 48)
        ])
    }

    private func loadSharedImage() {
        guard imageData == nil else {
            return
        }
        guard let provider = firstImageProvider() else {
            statusLabel.text = "No image found"
            instructionLabel.text = "Share a screenshot or photo, then choose IIRY from the share sheet."
            commitButton.isEnabled = false
            return
        }
        statusLabel.text = "Loading image"
        for type in [UTType.jpeg.identifier, UTType.png.identifier, "public.heic", UTType.image.identifier] {
            guard provider.hasItemConformingToTypeIdentifier(type) else {
                continue
            }
            provider.loadDataRepresentation(forTypeIdentifier: type) { [weak self] data, error in
                DispatchQueue.main.async {
                    guard let self else { return }
                    if let data {
                        self.imageData = data
                        self.imageType = type
                        self.imageView.image = UIImage(data: data)
                        self.statusLabel.text = "Ready for wallet commitment"
                        self.instructionLabel.text = "This will prepare the image in IIRY. The wallet step happens in the app."
                        self.commitButton.isEnabled = true
                    } else {
                        self.statusLabel.text = "Image could not be loaded"
                        self.instructionLabel.text = error?.localizedDescription ?? "Try sharing the screenshot again."
                        self.commitButton.isEnabled = false
                    }
                }
            }
            return
        }
        statusLabel.text = "Unsupported share"
        instructionLabel.text = "IIRY can commit screenshots and photos."
        commitButton.isEnabled = false
    }

    @objc
    private func commitImage() {
        if isPreparedForApp {
            extensionContext?.completeRequest(returningItems: nil)
            return
        }

        guard let imageData else {
            statusLabel.text = "No image is ready."
            return
        }

        do {
            try writeSharedImage(imageData, typeIdentifier: imageType)
            statusLabel.text = "Ready in IIRY"
            instructionLabel.text = "Tap Done, then open IIRY. Your image will appear with the commit button visible."
            commitButton.setTitle("Done", for: .normal)
            commitButton.backgroundColor = UIColor(red: 0.05, green: 0.48, blue: 0.32, alpha: 1)
            commitButton.isEnabled = true
            isPreparedForApp = true
        } catch {
            statusLabel.text = "Could not prepare image"
            instructionLabel.text = error.localizedDescription
        }
    }

    private func writeSharedImage(_ data: Data, typeIdentifier: String) throws {
        guard let directory = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroupIdentifier) else {
            throw HandoffError.appGroupUnavailable
        }

        let imageURL = directory.appendingPathComponent(Self.handoffImageName)
        let metadataURL = directory.appendingPathComponent(Self.handoffMetadataName)
        let metadata = SharedImageMetadata(
            typeIdentifier: typeIdentifier,
            stagedAt: ISO8601DateFormatter().string(from: Date())
        )

        try data.write(to: imageURL, options: [.atomic, .completeFileProtection])
        try JSONEncoder().encode(metadata).write(to: metadataURL, options: [.atomic, .completeFileProtection])
    }

    private func firstImageProvider() -> NSItemProvider? {
        let items = extensionContext?.inputItems.compactMap { $0 as? NSExtensionItem } ?? []
        let providers = items.flatMap { $0.attachments ?? [] }
        for provider in providers {
            for type in [UTType.jpeg.identifier, UTType.png.identifier, "public.heic", UTType.image.identifier] {
                if provider.hasItemConformingToTypeIdentifier(type) {
                    return provider
                }
            }
        }
        return nil
    }

    @objc
    private func cancel() {
        extensionContext?.completeRequest(returningItems: nil)
    }
}

private struct SharedImageMetadata: Encodable {
    let typeIdentifier: String
    let stagedAt: String
}

private enum HandoffError: LocalizedError {
    case appGroupUnavailable

    var errorDescription: String? {
        switch self {
        case .appGroupUnavailable:
            return "IIRY shared storage is unavailable. Reinstall the app with the share-extension entitlement."
        }
    }
}
