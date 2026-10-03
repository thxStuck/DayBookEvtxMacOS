import SwiftUI

@main
struct DayBookApp: App {
    @State private var app = AppModel()

    var body: some Scene {
        Window("DayBookEvtxMacOS", id: "main") {
            ContentView(app: app)
                .frame(minWidth: 1100, minHeight: 640)
                .defaultAppStorage(AppDefaults.store)
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("О программе DayBookEvtxMacOS") { AboutPanel.show() }
                LanguageMenu(app: app)
            }
            CommandGroup(after: .help) { HelpMenuItems() }
            CommandGroup(replacing: .newItem) {
                Button("Новый кейс из журналов…") { app.newCaseFromLogs() }
                    .keyboardShortcut("n")
                Button("Открыть кейс…") { app.openCasePanel() }
                    .keyboardShortcut("o")
                Divider()
                Button("Закрыть кейс") { app.closeCase() }
                    .keyboardShortcut("w", modifiers: [.command, .shift])
                    .disabled(app.caseModel == nil)
            }
            CommandMenu("Событие") {
                Button("Закладка") { app.caseModel?.toggleBookmarkOnSelection() }
                    .keyboardShortcut("b")
                    .disabled(app.caseModel?.selectedId == nil)
            }
        }
    }
}
