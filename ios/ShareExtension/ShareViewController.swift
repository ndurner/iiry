import UIKit
import UniformTypeIdentifiers

final class ShareViewController: UIViewController {
    private static let appGroupIdentifier = "group.de.ndurner.iiry"
    private static let handoffImageName = "shared-image.bin"
    private static let handoffMetadataName = "shared-image.json"

    private let statusLabel = UILabel()
    private let imageView = UIImageView()
    private let commitButton = UIButton(type: .system)
    private let cancelButton = UIButton(type: .system)
    private var imageData: Data?
    private var imageType = UTType.data.identifier

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
        view.backgroundColor = .systemBackground

        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .preferredFont(forTextStyle: .body)
        statusLabel.textColor = .secondaryLabel
        statusLabel.numberOfLines = 0
        statusLabel.text = "Preparing image..."

        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.contentMode = .scaleAspectFit
        imageView.backgroundColor = .secondarySystemBackground
        imageView.layer.cornerRadius = 8
        imageView.clipsToBounds = true

        commitButton.translatesAutoresizingMaskIntoConstraints = false
        commitButton.setTitle("Commit in IIRY", for: .normal)
        commitButton.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        commitButton.isEnabled = false
        commitButton.addTarget(self, action: #selector(commitImage), for: .touchUpInside)

        cancelButton.translatesAutoresizingMaskIntoConstraints = false
        cancelButton.setTitle("Cancel", for: .normal)
        cancelButton.addTarget(self, action: #selector(cancel), for: .touchUpInside)

        let buttons = UIStackView(arrangedSubviews: [cancelButton, commitButton])
        buttons.translatesAutoresizingMaskIntoConstraints = false
        buttons.axis = .horizontal
        buttons.distribution = .fillEqually
        buttons.spacing = 12

        view.addSubview(statusLabel)
        view.addSubview(imageView)
        view.addSubview(buttons)

        NSLayoutConstraint.activate([
            statusLabel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 22),
            statusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 18),
            statusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -18),

            imageView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 14),
            imageView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 18),
            imageView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -18),
            imageView.bottomAnchor.constraint(equalTo: buttons.topAnchor, constant: -14),

            buttons.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 18),
            buttons.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -18),
            buttons.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -18),
            buttons.heightAnchor.constraint(equalToConstant: 44)
        ])
    }

    private func loadSharedImage() {
        guard imageData == nil else {
            return
        }
        guard let provider = firstImageProvider() else {
            statusLabel.text = "Share an image with IIRY."
            commitButton.isEnabled = false
            return
        }
        statusLabel.text = "Loading image..."
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
                        self.statusLabel.text = "Image ready for IIRY."
                        self.commitButton.isEnabled = true
                    } else {
                        self.statusLabel.text = error?.localizedDescription ?? "The shared image could not be loaded."
                        self.commitButton.isEnabled = false
                    }
                }
            }
            return
        }
        statusLabel.text = "The shared item is not a readable image."
        commitButton.isEnabled = false
    }

    @objc
    private func commitImage() {
        guard let imageData else {
            statusLabel.text = "No image is ready."
            return
        }

        do {
            try writeSharedImage(imageData, typeIdentifier: imageType)
            statusLabel.text = "Image staged. Open IIRY now to continue."
            commitButton.setTitle("Staged for IIRY", for: .normal)
            commitButton.isEnabled = false
        } catch {
            statusLabel.text = error.localizedDescription
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
