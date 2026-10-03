import DaybookStore
import EvtxCore
import SwiftUI

/// Everything the import did, per file — nothing summarised away.
struct CaseInfoView: View {
    let model: CaseModel
    let dismiss: () -> Void
    @State private var flags: [Int: [String: Int]] = [:]

    private var store: CaseStore { model.store }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Сведения о кейсе").font(.title2.bold())
                Spacer()
                Button("Копировать таблицу (TSV)") { EventTableCoordinator.copy(tsv()) }
                Button("Закрыть", action: dismiss).keyboardShortcut(.defaultAction)
            }
            summary
            Divider()
            ScrollView([.horizontal, .vertical]) {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                    GridRow {
                        ForEach(Self.headers, id: \.self) { Text($0).font(.caption.bold()).foregroundStyle(.secondary) }
                    }
                    Divider()
                    ForEach(store.sources) { s in
                        GridRow {
                            ForEach(Array(cells(s).enumerated()), id: \.offset) { i, c in
                                Text(c)
                                    .font(i == 0 ? .callout.weight(.medium) : .callout.monospacedDigit())
                                    .foregroundStyle(highlight(i, s) ? Color.orange : Color.primary)
                                    .textSelection(.enabled)
                                    .lineLimit(1)
                            }
                        }
                        .help(s.path)
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .padding(20)
        .frame(minWidth: 1100, minHeight: 600)
        .task {
            let store = self.store
            flags = await Task.detached { (try? store.flagCountsBySource()) ?? [:] }.value
        }
    }

    private var summary: some View {
        let m = store.meta
        let yes = String(localized: "да"), no = String(localized: "нет")
        func opt(_ k: String) -> String { m[k] == "1" ? yes : (m[k] == "0" ? no : "—") }
        return VStack(alignment: .leading, spacing: 4) {
            Text("Событий в кейсе: \(store.eventCount.formatted()) · файлов: \(store.sources.count) · создан: \(m["created"] ?? "—") · схема \(m["schema"] ?? "?")")
            Text("Восстановлено из slack: найдено \(m["carvedFound"] ?? "—"), уникальных \(m["carvedKept"] ?? "—") · схлопнуто копий: \(m["duplicates"] ?? "—") · ошибок разбора: \(m["parseErrors"] ?? "—")")
            Text("Параметры импорта: carving \(opt("option.carveSlack")) · объединение копий \(opt("option.mergeDuplicates")) · SHA-256 \(opt("option.hashSources")) · полнотекстовый индекс \(store.fullTextReady ? yes : no)")
            if let failed = m["failedFiles"], !failed.isEmpty {
                Text("Не удалось открыть:\n" + failed).foregroundStyle(.red).textSelection(.enabled)
            }
            Text("Время событий хранится в UTC (FILETIME, 100 нс); отображение — в выбранном поясе.")
                .foregroundStyle(.secondary)
        }
        .font(.callout)
    }

    static let headers: [String] = [
        String(localized: "Файл"), String(localized: "Размер"), "SHA-256", String(localized: "Версия"), "Dirty",
        String(localized: "Чанков (заголовок / физ.)"), String(localized: "Пустых"),
        String(localized: "За заголовком: новые / устар."), String(localized: "CRC заг. / данных"),
        String(localized: "Хвост, байт"), String(localized: "Событий"), String(localized: "Восстановл."),
        String(localized: "Копий схлопнуто"), String(localized: "Первое"), String(localized: "Последнее"),
        String(localized: "Флаги записей"),
    ]

    private func cells(_ s: SourceInfo) -> [String] {
        func n(_ v: Int?) -> String { v.map { $0.formatted() } ?? "—" }
        let f = flags[s.id] ?? [:]
        let flagText = f.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", ")
        return [
            s.name,
            ByteCountFormatter.string(fromByteCount: s.size, countStyle: .file),
            s.sha256.isEmpty ? "—" : s.sha256,
            s.formatVersion ?? "—",
            s.dirty ? String(localized: "да") : String(localized: "нет"),
            "\(s.headerChunks) / \(s.chunks)",
            n(s.emptyChunks),
            "\(n(s.beyondHeaderNew)) / \(n(s.beyondHeaderStale))",
            "\(n(s.badHeaderCRC)) / \(n(s.badDataCRC))",
            n(s.trailingBytes),
            s.records.formatted(),
            s.carved.formatted(),
            s.duplicates.formatted(),
            s.firstTs.map { model.formatter.string($0) } ?? "—",
            s.lastTs.map { model.formatter.string($0) } ?? "—",
            flagText.isEmpty ? "—" : flagText,
        ]
    }

    /// Columns worth a second look are highlighted (stale header, CRC errors, …).
    private func highlight(_ column: Int, _ s: SourceInfo) -> Bool {
        switch column {
        case 7: (s.beyondHeaderNew ?? 0) + (s.beyondHeaderStale ?? 0) > 0
        case 8: (s.badHeaderCRC ?? 0) + (s.badDataCRC ?? 0) > 0
        case 9: (s.trailingBytes ?? 0) > 0
        case 15: (flags[s.id]?["parseError"] ?? 0) > 0
        default: false
        }
    }

    private func tsv() -> String {
        ([Self.headers + [String(localized: "Путь")]] + store.sources.map { cells($0) + [$0.path] })
            .map { $0.joined(separator: "\t") }.joined(separator: "\n")
    }
}
