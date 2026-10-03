import DaybookStore
import SwiftUI

struct ContentView: View {
    @Bindable var app: AppModel

    var body: some View {
        Group {
            if let c = app.caseModel {
                CaseView(model: c)
                    .id(ObjectIdentifier(c))
            } else {
                WelcomeView(app: app)
            }
        }
        .sheet(item: $app.importState) { state in
            ImportSheet(state: state) { app.importState = nil }
        }
        .sheet(item: $app.pendingImport) { p in
            ImportOptionsSheet(pending: p,
                               start: { app.startImport(sources: p.sources, caseURL: p.caseURL, options: $0) },
                               cancel: { app.pendingImport = nil })
        }
        .alert("Ошибка", isPresented: Binding(get: { app.alert != nil }, set: { if !$0 { app.alert = nil } })) {
            Button("OK") { app.alert = nil }
        } message: {
            Text(app.alert ?? "")
        }
        .task { SnapshotRunner.runIfRequested(app: app) }
    }
}

extension ImportState: Identifiable {
    var id: ObjectIdentifier { ObjectIdentifier(self) }
}

struct WelcomeView: View {
    let app: AppModel

    var body: some View {
        VStack(spacing: 22) {
            Image(systemName: "list.bullet.rectangle.portrait")
                .font(.system(size: 54))
                .foregroundStyle(.tint)
            VStack(spacing: 6) {
                Text("DayBookEvtxMacOS").font(.largeTitle.bold())
                Text("Просмотр и анализ журналов Windows (.evtx) на macOS")
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 12) {
                Button {
                    app.newCaseFromLogs()
                } label: {
                    Label("Новый кейс из журналов…", systemImage: "folder.badge.plus")
                        .frame(minWidth: 220)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                .keyboardShortcut("n")

                Button {
                    app.openCasePanel()
                } label: {
                    Label("Открыть кейс…", systemImage: "tray.and.arrow.up")
                        .frame(minWidth: 160)
                }
                .controlSize(.large)
            }
            if !app.recentCases.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Недавние кейсы").font(.headline)
                    ForEach(app.recentCases, id: \.self) { url in
                        Button {
                            app.open(url)
                        } label: {
                            HStack {
                                Image(systemName: "doc.text")
                                Text(url.deletingPathExtension().lastPathComponent)
                                Text(url.deletingLastPathComponent().path)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.head)
                            }
                        }
                        .buttonStyle(.link)
                    }
                }
                .frame(maxWidth: 560, alignment: .leading)
                .padding(.top, 8)
            }
            Text("Исходные файлы открываются только для чтения и не изменяются.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ImportSheet: View {
    let state: ImportState
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Импорт журналов").font(.title2.bold())
            Text(state.sources.map(\.lastPathComponent).joined(separator: ", "))
                .foregroundStyle(.secondary)
                .lineLimit(2)
            if let error = state.error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                HStack {
                    Spacer()
                    Button("Закрыть", action: dismiss).keyboardShortcut(.defaultAction)
                }
            } else {
                Text(state.phaseTitle).font(.headline)
                if state.phase == .writing {
                    ProgressView(value: state.fraction)
                } else {
                    ProgressView().progressViewStyle(.linear)
                }
                HStack {
                    if state.events > 0 { Text("\(state.events.formatted()) событий") }
                    Spacer()
                    TimelineView(.periodic(from: state.startedAt, by: 0.5)) { ctx in
                        Text("\(String(format: "%.1f", ctx.date.timeIntervalSince(state.startedAt))) с")
                            .monospacedDigit()
                    }
                }
                .font(.callout)
                .foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Отмена") { state.cancel.set() }
                        .keyboardShortcut(.cancelAction)
                }
            }
        }
        .padding(24)
        .frame(width: 520)
    }
}


/// Import options, shown before every import so nothing happens implicitly.
struct ImportOptionsSheet: View {
    let pending: PendingImport
    let start: (ImportOptions) -> Void
    let cancel: () -> Void
    @AppStorage("import.carveSlack") private var carveSlack = true
    @AppStorage("import.mergeDuplicates") private var mergeDuplicates = true
    @AppStorage("import.hashSources") private var hashSources = true
    @AppStorage("import.runDetections") private var runDetections = true

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Параметры импорта").font(.title2.bold())
            VStack(alignment: .leading, spacing: 2) {
                Text("Источники:").font(.headline)
                ForEach(pending.sources, id: \.self) { Text($0.path).font(.callout).textSelection(.enabled) }
                Text("Кейс: \(pending.caseURL.path)").font(.callout).foregroundStyle(.secondary).padding(.top, 4)
            }
            Divider()
            option($carveSlack, "Восстанавливать записи из slack-области чанков",
                   "Остатки старых записей после freeSpaceOffset. Каждая восстановленная запись помечается флагом carved.")
            option($mergeDuplicates, "Объединять одинаковые записи",
                   "Одна и та же запись из живого журнала, теневой копии и slack показывается одним событием с флагом «есть копии»; все места нахождения видны в деталях. Если выключить — каждая копия будет отдельной строкой.")
            option($hashSources, "Считать SHA-256 исходных файлов",
                   "Для фиксации исходных данных (chain of custody): хеш попадает в сведения о кейсе и в экспорт.")
            option($runDetections, "Запустить Sigma-детекты после импорта",
                   "Правила SigmaHQ и Hayabusa из поставки (DRL 1.1) и папка своих правил, если выбрана. Идёт в фоне после открытия кейса; результаты сохраняются в кейсе, их можно перезапустить на экране «Детекты».")
            Text("Исходные файлы открываются только для чтения и не изменяются.")
                .font(.footnote).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Отмена", action: cancel).keyboardShortcut(.cancelAction)
                Button("Начать импорт") {
                    var o = ImportOptions()
                    o.carveSlack = carveSlack
                    o.mergeDuplicates = mergeDuplicates
                    o.hashSources = hashSources
                    start(o)
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 600)
    }

    private func option(_ value: Binding<Bool>, _ title: LocalizedStringKey, _ note: LocalizedStringKey) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Toggle(title, isOn: value)
            Text(note).font(.caption).foregroundStyle(.secondary).padding(.leading, 20)
        }
    }
}
