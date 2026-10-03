import Foundation

/// The app's settings. Automated snapshot runs (`-snapshot`) use a separate store, emptied at
/// launch: they must never change the user's recent cases, query history, panel sizes or other
/// choices.
enum AppDefaults {
    static let store: UserDefaults = {
        guard ProcessInfo.processInfo.arguments.contains("-snapshot") else { return .standard }
        let suite = "app.daybook.evtx.snapshot"
        UserDefaults.standard.removePersistentDomain(forName: suite)
        return UserDefaults(suiteName: suite) ?? .standard
    }()
}
