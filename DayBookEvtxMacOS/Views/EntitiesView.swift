import DaybookStore
import EvtxCore
import SwiftUI

/// Sortable row model for the entity tables.
nonisolated struct EntityRowItem: Identifiable, Sendable {
    let info: EntityInfo
    var id: Int { info.id }
    var display: String { info.display }
    var detail: String
    var first: Int64 { info.firstTs ?? 0 }
    var last: Int64 { info.lastTs ?? 0 }
    var events: Int { info.events }
    var roles: String

    init(_ e: EntityInfo) {
        info = e
        switch e.kind {
        case .user: detail = [e.sid, e.aliases.isEmpty ? nil : e.aliases.prefix(3).joined(separator: ", ")].compactMap { $0 }.joined(separator: " · ")
        case .host, .ip: detail = e.aliases.prefix(4).joined(separator: ", ")
        }
        roles = e.roles.sorted { $0.value > $1.value }.compactMap { r in
            EntityRole(rawValue: r.key).map { "\(EntitiesView.roleName($0)) \(r.value)" }
        }.joined(separator: ", ")
    }
}

struct EntitiesView: View {
    let model: CaseModel
    let kind: EntityKind
    @State private var sortOrder = [KeyPathComparator(\EntityRowItem.events, order: .reverse)]
    @State private var search = ""
    @State private var selection: Int?
    @AppStorage("hideBuiltinEntities") private var hideBuiltin = false

    static func roleName(_ r: EntityRole) -> String {
        switch r {
        case .logging: String(localized: "журнал")
        case .source: String(localized: "источник")
        case .target: String(localized: "цель")
        case .subject: String(localized: "субъект")
        case .account: String(localized: "уч. запись компьютера")
        case .destination: String(localized: "назначение")
        case .system: String(localized: "контекст события")
        }
    }

    private var rows: [EntityRowItem] {
        let all = model.entities[kind] ?? []
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        return all.filter { e in
            (!hideBuiltin || !e.builtin)
                && (q.isEmpty || e.display.lowercased().contains(q) || e.aliases.contains { $0.lowercased().contains(q) }
                    || (e.sid?.lowercased().contains(q) ?? false))
        }.map(EntityRowItem.init).sorted(using: sortOrder)
    }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    TextField("Поиск по имени, алиасу, SID", text: $search)
                        .textFieldStyle(.roundedBorder)
                        .frame(minWidth: 120, maxWidth: 320)
                    if kind == .user { Toggle("Скрыть встроенные учётки", isOn: $hideBuiltin) }
                    Spacer()
                    if model.entities[kind] == nil { ProgressView().controlSize(.small) }
                    Text("\(rows.count.formatted()) из \((model.entities[kind]?.count ?? 0).formatted())")
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                .padding(8)
                Divider()
                Table(rows, selection: $selection, sortOrder: $sortOrder) {
                    TableColumn("Имя", value: \.display) { r in
                        HStack(spacing: 4) {
                            if r.info.builtin { Image(systemName: "gearshape").foregroundStyle(.secondary).help("Встроенная учётная запись") }
                            Text(r.display).fontWeight(.medium)
                        }
                    }
                    .width(min: 110, ideal: 220)
                    TableColumn(kind == .user ? String(localized: "SID · другие написания") : String(localized: "Другие написания"), value: \.detail)
                        .width(min: 60, ideal: 260)
                    TableColumn("Первое появление", value: \.first) { r in Text(model.formatter.string(r.first)).monospacedDigit() }
                        .width(min: 90, ideal: 175)
                    TableColumn("Последнее", value: \.last) { r in Text(model.formatter.string(r.last)).monospacedDigit() }
                        .width(min: 90, ideal: 175)
                    TableColumn("Событий", value: \.events) { r in Text(r.events.formatted()).monospacedDigit() }
                        .width(min: 50, ideal: 80)
                    TableColumn("Роли", value: \.roles)
                        .width(min: 60, ideal: 260)
                }
                .contextMenu(forSelectionType: Int.self) { ids in
                    if let id = ids.first, let e = model.entity(id) {
                        Button("Показать все события") { model.showEvents(of: e) }
                        Button("Показать в таймлайне") { model.showEvents(of: e, timeline: true) }
                        Button("Исключить из событий") { model.showEvents(of: e, negated: true) }
                        Divider()
                        Button("Копировать имя") { EventTableCoordinator.copy(e.display) }
                        if let sid = e.sid { Button("Копировать SID") { EventTableCoordinator.copy(sid) } }
                    }
                } primaryAction: { ids in
                    if let id = ids.first, let e = model.entity(id) { model.showEvents(of: e) }
                }
                .onChange(of: selection) { _, id in model.selectEntity(id.flatMap { model.entity($0) }) }
            }
            .frame(minWidth: 420, maxWidth: .infinity, maxHeight: .infinity)
            EntityDetailView(model: model)
                .frame(minWidth: 240, idealWidth: 340, maxWidth: 480, maxHeight: .infinity)
        }
        .onAppear { model.loadEntities(kind) }
    }
}

struct EntityDetailView: View {
    let model: CaseModel

    var body: some View {
        if let e = model.selectedEntity {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(e.display).font(.title3.bold()).textSelection(.enabled)
                    if let sid = e.sid { labeled("SID", sid) }
                    if !e.aliases.isEmpty { labeled(String(localized: "Другие написания"), e.aliases.joined(separator: "\n")) }
                    labeled(String(localized: "Первое появление"), e.firstTs.map { model.formatter.string($0) } ?? "—")
                    labeled(String(localized: "Последнее"), e.lastTs.map { model.formatter.string($0) } ?? "—")
                    labeled(String(localized: "Событий"), e.events.formatted())
                    HStack {
                        Button("Все события") { model.showEvents(of: e) }
                        Button("Таймлайн") { model.showEvents(of: e, timeline: true) }
                    }
                    Divider()
                    Text("Связи").font(.headline)
                    if model.entityLinks.isEmpty {
                        Text("Нет связей или загрузка…").foregroundStyle(.secondary)
                    }
                    ForEach(model.entityLinks.prefix(150), id: \.other) { link in
                        if let other = model.entity(link.other) {
                            HStack(alignment: .firstTextBaseline) {
                                Image(systemName: icon(other.kind)).foregroundStyle(.secondary)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(other.display).lineLimit(1)
                                    Text("\(link.count.formatted()) соб. · \(model.formatter.string(link.firstTs)) – \(model.formatter.string(link.lastTs))")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("События") {
                                    model.addFilter(key: CaseModel.filterKey(other.kind), value: CaseModel.filterValue(other), negated: false)
                                    model.showEvents(of: e)
                                }
                                .controlSize(.small)
                                .help("События, где встречаются обе сущности")
                            }
                        }
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Выберите сущность", systemImage: "person.2.circle",
                                   description: Text("Здесь будут её связи с хостами, пользователями и IP."))
        }
    }

    private func icon(_ k: EntityKind) -> String {
        switch k {
        case .host: "desktopcomputer"
        case .user: "person"
        case .ip: "network"
        }
    }

    private func labeled(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }
}
