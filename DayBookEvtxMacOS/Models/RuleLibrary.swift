import DaybookSigma
import Foundation

/// Detection rules shipped with the app (SigmaHQ + Hayabusa, DRL 1.1) plus an optional
/// folder of the analyst's own rules.
nonisolated enum RuleLibrary {
    static let customFolderKey = "rules.customFolder"

    static var packURL: URL? {
        Bundle.main.url(forResource: "rules", withExtension: "json")
            ?? Bundle.main.url(forResource: "rules", withExtension: "json", subdirectory: "Rules")
    }

    static var licenseText: String {
        let url = Bundle.main.url(forResource: "DRL-1.1", withExtension: "md")
            ?? Bundle.main.url(forResource: "DRL-1.1", withExtension: "md", subdirectory: "Rules")
        return url.flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? "https://github.com/SigmaHQ/Detection-Rule-License"
    }

    static func load(customFolder: String?) throws -> SigmaRuleSet {
        guard let url = packURL else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSLocalizedDescriptionKey: String(localized: "В приложении нет пакета правил rules.json")])
        }
        var set = try SigmaRuleSet.pack(Data(contentsOf: url))
        if let path = customFolder, !path.isEmpty {
            let folder = URL(fileURLWithPath: path)
            set.merge(.folder(folder, name: String(localized: "Свои: ") + folder.lastPathComponent))
        }
        return set
    }
}
