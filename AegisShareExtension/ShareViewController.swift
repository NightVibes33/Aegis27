import UIKit
import UniformTypeIdentifiers

final class ShareViewController: UIViewController {
    private static let boundaryType = "com.nightvibes33.canarybox.boundary-envelope"
    private static let callbackScheme = "aegis27-boundary"
    private var didStart = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.text = "Sending the bounded CanaryBox challenge to Aegis27…"
        label.numberOfLines = 0
        label.textAlignment = .center
        label.font = .preferredFont(forTextStyle: .body)
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
            label.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !didStart else { return }
        didStart = true
        forwardFirstBoundedAttachment()
    }

    private func forwardFirstBoundedAttachment() {
        let providers = (extensionContext?.inputItems as? [NSExtensionItem] ?? [])
            .flatMap { $0.attachments ?? [] }
        guard let provider = providers.first(where: {
            $0.hasItemConformingToTypeIdentifier(Self.boundaryType) ||
                $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) ||
                $0.hasItemConformingToTypeIdentifier(UTType.json.identifier)
        }) else {
            finish()
            return
        }

        let typeIdentifier: String
        if provider.hasItemConformingToTypeIdentifier(Self.boundaryType) {
            typeIdentifier = Self.boundaryType
        } else if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            typeIdentifier = UTType.fileURL.identifier
        } else {
            typeIdentifier = UTType.json.identifier
        }

        provider.loadItem(forTypeIdentifier: typeIdentifier, options: nil) { [weak self] item, _ in
            guard let self else { return }
            let data: Data?
            if let url = item as? URL {
                data = try? Data(contentsOf: url, options: [.mappedIfSafe])
            } else if let value = item as? Data {
                data = value
            } else if let text = item as? String {
                data = Data(text.utf8)
            } else {
                data = nil
            }

            guard let data, data.count <= 128 * 1024 else {
                self.finish()
                return
            }
            self.openHost(with: data)
        }
    }

    private func openHost(with data: Data) {
        var components = URLComponents()
        components.scheme = Self.callbackScheme
        components.host = "share-import"
        components.queryItems = [
            URLQueryItem(name: "payload", value: data.base64URLEncodedString())
        ]
        guard let url = components.url else {
            finish()
            return
        }
        extensionContext?.open(url) { [weak self] _ in
            self?.finish()
        }
    }

    private func finish() {
        extensionContext?.completeRequest(returningItems: nil)
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
