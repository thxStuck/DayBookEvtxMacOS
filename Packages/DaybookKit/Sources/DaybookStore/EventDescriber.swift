import Foundation

/// One-line human-readable description of key DFIR events (the "text" column of a
/// SIEM), built from the event's fields. Codes are translated: logon types, NTSTATUS
/// failure reasons, Kerberos encryption types and `%%NNNN` parameter messages.
public enum EventDescriber {
    public typealias Fields = (String) -> String?

    public static func describe(provider: String, channel: String, eventId: UInt16, field: Fields) -> String? {
        func f(_ name: String) -> String? {
            guard let v = field(name)?.trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty, v != "-" else { return nil }
            return v
        }
        func user(_ name: String, _ domain: String? = nil) -> String? {
            guard let n = f(name) else { return nil }
            if let d = domain.flatMap(f), !n.contains("\\") { return d + "\\" + n }
            return n
        }
        func src(_ host: String?, _ ip: String?) -> String {
            let h = host.flatMap(f), i = ip.flatMap(f).map { $0.hasPrefix("::ffff:") ? String($0.dropFirst(7)) : $0 }
            switch (h, i) {
            case let (h?, i?): return String(localized: " с \(h) (\(i))")
            case let (h?, nil): return String(localized: " с \(h)")
            case let (nil, i?): return String(localized: " с \(i)")
            default: return ""
            }
        }
        func short(_ s: String?, _ n: Int = 160) -> String {
            guard let s else { return "" }
            let one = s.replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\n", with: " ")
            return one.count > n ? String(one.prefix(n)) + "…" : one
        }
        let sysmon = provider == "Microsoft-Windows-Sysmon"

        if sysmon {
            switch eventId {
            case 1: return String(localized: "Процесс \(f("Image") ?? "?"): \(short(f("CommandLine"))) ← \(f("ParentImage") ?? "?")\(f("User").map { " [\($0)]" } ?? "")")
            case 2: return String(localized: "Изменено время создания файла \(f("TargetFilename") ?? "?") (\(f("Image") ?? "?"))")
            case 3: return String(localized: "Сеть: \(f("Image") ?? "?") → \(f("DestinationIp") ?? "?"):\(f("DestinationPort") ?? "?")\(f("DestinationHostname").map { " (\($0))" } ?? "")")
            case 5: return String(localized: "Процесс завершён: \(f("Image") ?? "?")")
            case 6: return String(localized: "Загружен драйвер \(f("ImageLoaded") ?? "?") (подпись: \(f("Signature") ?? "?"))")
            case 7: return String(localized: "Модуль \(f("ImageLoaded") ?? "?") загружен в \(f("Image") ?? "?")")
            case 8: return "CreateRemoteThread: \(f("SourceImage") ?? "?") → \(f("TargetImage") ?? "?")"
            case 10:
                let target = f("TargetImage") ?? "?"
                let warn = target.lowercased().hasSuffix("\\lsass.exe") ? "⚠ " : ""
                return String(localized: "\(warn)Доступ к процессу: \(f("SourceImage") ?? "?") → \(target) (права \(f("GrantedAccess") ?? "?"))")
            case 11: return String(localized: "Создан файл \(f("TargetFilename") ?? "?") (\(f("Image") ?? "?"))")
            case 12, 13, 14:
                return String(localized: "Реестр \(f("EventType") ?? ""): \(f("TargetObject") ?? "?")\(f("Details").map { " = \(short($0, 80))" } ?? "") (\(f("Image") ?? "?"))")
            case 15: return String(localized: "Альтернативный поток данных \(f("TargetFilename") ?? "?")")
            case 17, 18: return String(localized: "Именованный канал \(f("PipeName") ?? "?") (\(f("Image") ?? "?"))")
            case 22: return String(localized: "DNS-запрос \(f("QueryName") ?? "?") → \(short(f("QueryResults"), 80)) (\(f("Image") ?? "?"))")
            case 23, 26: return String(localized: "Удалён файл \(f("TargetFilename") ?? "?") (\(f("Image") ?? "?"))")
            case 25: return String(localized: "Подмена процесса \(f("Image") ?? "?") (\(f("Type") ?? ""))")
            default: return nil
            }
        }

        switch (channel, eventId) {
        case ("Security", 4624):
            let lt = f("LogonType")
            return String(localized: "Успешный вход \(user("TargetUserName", "TargetDomainName") ?? "?") (тип \(lt ?? "?")\(lt.flatMap(logonTypeName).map { ", \($0)" } ?? ""))\(src("WorkstationName", "IpAddress"))\(f("AuthenticationPackageName").map { " · \($0)" } ?? "")")
        case ("Security", 4625):
            let lt = f("LogonType")
            let reason = f("SubStatus").flatMap(ntStatus) ?? f("Status").flatMap(ntStatus) ?? f("FailureReason").map(param) ?? "?"
            return String(localized: "Неудачный вход \(user("TargetUserName", "TargetDomainName") ?? "?") (тип \(lt ?? "?")\(lt.flatMap(logonTypeName).map { ", \($0)" } ?? ""))\(src("WorkstationName", "IpAddress")): \(reason)")
        case ("Security", 4634): return String(localized: "Выход \(user("TargetUserName", "TargetDomainName") ?? "?") (сеанс \(f("TargetLogonId") ?? "?"), тип \(f("LogonType") ?? "?"))")
        case ("Security", 4647): return String(localized: "Пользователь \(user("TargetUserName", "TargetDomainName") ?? "?") инициировал выход")
        case ("Security", 4648):
            return String(localized: "Явные учётные данные: \(user("SubjectUserName", "SubjectDomainName") ?? "?") → \(user("TargetUserName", "TargetDomainName") ?? "?") на \(f("TargetServerName") ?? "?")\(f("ProcessName").map { " (\($0))" } ?? "")")
        case ("Security", 4672): return String(localized: "Специальные привилегии: \(user("SubjectUserName", "SubjectDomainName") ?? "?")")
        case ("Security", 4688):
            return String(localized: "Процесс \(f("NewProcessName") ?? "?"): \(short(f("CommandLine"))) ← \(f("ParentProcessName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4689): return String(localized: "Завершён процесс \(f("ProcessName") ?? "?")")
        case ("Security", 4697): return String(localized: "Установлена служба \(f("ServiceName") ?? "?"): \(short(f("ServiceFileName"))) [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4698): return String(localized: "Создана задача \(f("TaskName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4699): return String(localized: "Удалена задача \(f("TaskName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4700): return String(localized: "Включена задача \(f("TaskName") ?? "?")")
        case ("Security", 4701): return String(localized: "Отключена задача \(f("TaskName") ?? "?")")
        case ("Security", 4702): return String(localized: "Изменена задача \(f("TaskName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4720): return String(localized: "Создана учётная запись \(user("TargetUserName", "TargetDomainName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4722): return String(localized: "Включена учётная запись \(user("TargetUserName", "TargetDomainName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4723): return String(localized: "Попытка смены пароля \(user("TargetUserName", "TargetDomainName") ?? "?")")
        case ("Security", 4724): return String(localized: "Сброс пароля \(user("TargetUserName", "TargetDomainName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4725): return String(localized: "Отключена учётная запись \(user("TargetUserName", "TargetDomainName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4726): return String(localized: "Удалена учётная запись \(user("TargetUserName", "TargetDomainName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4738): return String(localized: "Изменена учётная запись \(user("TargetUserName", "TargetDomainName") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4740): return String(localized: "Учётная запись заблокирована: \(f("TargetUserName") ?? "?")\(f("TargetDomainName").map { String(localized: " (источник \($0))") } ?? "")")
        case ("Security", 4767): return String(localized: "Учётная запись разблокирована: \(f("TargetUserName") ?? "?")")
        case ("Security", 4728), ("Security", 4732), ("Security", 4756):
            return String(localized: "В группу \(user("TargetUserName", "TargetDomainName") ?? "?") добавлен \(memberName(f("MemberName")) ?? f("MemberSid") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4729), ("Security", 4733), ("Security", 4757):
            return String(localized: "Из группы \(user("TargetUserName", "TargetDomainName") ?? "?") удалён \(memberName(f("MemberName")) ?? f("MemberSid") ?? "?") [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4768):
            let st = f("Status")
            return String(localized: "Kerberos TGT для \(user("TargetUserName", "TargetDomainName") ?? "?")\(src(nil, "IpAddress"))\(st.map { $0 == "0x0" ? "" : ": " + (kerberosError($0) ?? $0) } ?? "")\(f("PreAuthType") == "0" ? String(localized: " ⚠ без преаутентификации") : "")")
        case ("Security", 4769):
            let enc = f("TicketEncryptionType")
            let rc4 = enc.map { ["0x17", "0x18"].contains($0.lowercased()) } ?? false
            return String(localized: "Kerberos TGS \(f("ServiceName") ?? "?") для \(f("TargetUserName") ?? "?")\(src(nil, "IpAddress"))\(enc.flatMap(encryptionType).map { " · \($0)" } ?? "")\(rc4 ? " ⚠ RC4" : "")")
        case ("Security", 4770): return String(localized: "Продлён билет Kerberos \(f("ServiceName") ?? "?") для \(f("TargetUserName") ?? "?")")
        case ("Security", 4771): return String(localized: "Ошибка преаутентификации Kerberos \(f("TargetUserName") ?? "?")\(src(nil, "IpAddress")): \(f("Status").flatMap(kerberosError) ?? f("Status") ?? "?")")
        case ("Security", 4776):
            let st = f("Status")
            return String(localized: "NTLM-проверка \(f("TargetUserName") ?? "?")\(src("Workstation", nil))\(st.map { $0 == "0x0" ? String(localized: " · успешно") : ": " + (ntStatus($0) ?? $0) } ?? "")")
        case ("Security", 4778): return String(localized: "RDP: переподключение \(user("AccountName", "AccountDomain") ?? "?")\(src("ClientName", "ClientAddress"))")
        case ("Security", 4779): return String(localized: "RDP: отключение \(user("AccountName", "AccountDomain") ?? "?")\(src("ClientName", "ClientAddress"))")
        case ("Security", 4616): return String(localized: "Изменено системное время: \(f("PreviousTime") ?? "?") → \(f("NewTime") ?? "?") (\(f("ProcessName") ?? "?"))")
        case ("Security", 4662):
            let props = (f("Properties") ?? "").lowercased()
            let dcsync = props.contains("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") || props.contains("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
                || props.contains("89e95b76-444d-4c62-991a-0facbeda640c")
            let object = f("ObjectName") ?? "?", subject = user("SubjectUserName", "SubjectDomainName") ?? "?"
            return dcsync ? String(localized: "⚠ Репликация каталога (возможен DCSync): \(object) [\(subject)]")
                : String(localized: "Операция над объектом AD: \(object) [\(subject)]")
        case ("Security", 4719): return String(localized: "Изменена политика аудита [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 4739): return String(localized: "Изменена политика домена \(f("DomainName") ?? "")")
        case ("Security", 4794): return String(localized: "Попытка задать пароль DSRM [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 5140): return String(localized: "Доступ к сетевой папке \(f("ShareName") ?? "?")\(src(nil, "IpAddress")) [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 5145): return String(localized: "Проверка доступа: \(f("ShareName") ?? "?")\\\(f("RelativeTargetName") ?? "")\(src(nil, "IpAddress")) [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 1102): return String(localized: "⚠ Журнал безопасности очищен [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("Security", 1100): return String(localized: "Служба журналов событий остановлена")
        case ("Security", 4608): return String(localized: "Запуск Windows")
        case ("Security", 4609): return String(localized: "Завершение работы Windows")
        case ("System", 7045):
            return String(localized: "Установлена служба \(f("ServiceName") ?? "?"): \(short(f("ImagePath"))) (\(f("StartType") ?? "?"), \(f("AccountName") ?? "?"))")
        case ("System", 7036): return String(localized: "Служба \(f("param1") ?? "?"): \(f("param2") ?? "?")")
        case ("System", 7040): return String(localized: "Тип запуска службы \(f("param1") ?? "?"): \(f("param2") ?? "?") → \(f("param3") ?? "?")")
        case ("System", 7034): return String(localized: "Служба \(f("param1") ?? "?") неожиданно завершилась")
        case ("System", 104): return String(localized: "⚠ Журнал \(f("Channel") ?? "?") очищен [\(user("SubjectUserName", "SubjectDomainName") ?? "?")]")
        case ("System", 6005): return String(localized: "Служба журналов событий запущена")
        case ("System", 6006): return String(localized: "Служба журналов событий остановлена")
        case ("System", 6008): return String(localized: "Предыдущее завершение работы было непредвиденным")
        case ("System", 6011): return String(localized: "NetBIOS/DNS-имя компьютера изменено")
        case ("System", 1) where provider == "Microsoft-Windows-Kernel-General":
            return String(localized: "Изменено системное время: \(f("OldTime") ?? "?") → \(f("NewTime") ?? "?")")
        case ("System", 12) where provider == "Microsoft-Windows-Kernel-General": return String(localized: "Запуск ОС")
        case ("System", 13) where provider == "Microsoft-Windows-Kernel-General": return String(localized: "Завершение работы ОС")
        case ("Microsoft-Windows-PowerShell/Operational", 4104):
            return "ScriptBlock \(f("MessageNumber") ?? "1")/\(f("MessageTotal") ?? "1"): \(short(f("ScriptBlockText"), 200))"
        case ("Microsoft-Windows-PowerShell/Operational", 4103): return String(localized: "Модуль PowerShell: \(short(f("Payload"), 200))")
        case ("Microsoft-Windows-PowerShell/Operational", 40961): return String(localized: "Запуск консоли PowerShell")
        case ("Microsoft-Windows-TaskScheduler/Operational", 106): return String(localized: "Зарегистрирована задача \(f("TaskName") ?? "?") [\(f("UserContext") ?? "?")]")
        case ("Microsoft-Windows-TaskScheduler/Operational", 140): return String(localized: "Изменена задача \(f("TaskName") ?? "?") [\(f("UserName") ?? "?")]")
        case ("Microsoft-Windows-TaskScheduler/Operational", 141): return String(localized: "Удалена задача \(f("TaskName") ?? "?") [\(f("UserName") ?? "?")]")
        case ("Microsoft-Windows-TaskScheduler/Operational", 200): return String(localized: "Запуск действия задачи \(f("TaskName") ?? "?"): \(f("ActionName") ?? "?")")
        case ("Microsoft-Windows-TaskScheduler/Operational", 201): return String(localized: "Действие задачи \(f("TaskName") ?? "?") завершено (код \(f("ResultCode") ?? "?"))")
        case ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 21): return String(localized: "RDP: вход \(f("User") ?? "?") с \(f("Address") ?? "?") (сеанс \(f("SessionID") ?? "?"))")
        case ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 22): return String(localized: "RDP: запуск оболочки \(f("User") ?? "?") с \(f("Address") ?? "?")")
        case ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 23): return String(localized: "RDP: выход \(f("User") ?? "?")")
        case ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 24): return String(localized: "RDP: сеанс отключён \(f("User") ?? "?") с \(f("Address") ?? "?")")
        case ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 25): return String(localized: "RDP: переподключение \(f("User") ?? "?") с \(f("Address") ?? "?")")
        case ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 1149):
            return String(localized: "RDP: аутентификация \(f("Param2").map { $0 + "\\" } ?? "")\(f("Param1") ?? "?") с \(f("Param3") ?? "?")")
        case ("Microsoft-Windows-Windows Defender/Operational", 1116):
            return String(localized: "⚠ Defender обнаружил \(f("Threat Name") ?? "?") в \(short(f("Path"), 120))")
        case ("Microsoft-Windows-Windows Defender/Operational", 1117):
            return String(localized: "Defender: действие над \(f("Threat Name") ?? "?") — \(f("Action Name") ?? "?")")
        case ("Microsoft-Windows-Windows Defender/Operational", 5001): return String(localized: "⚠ Defender: защита в реальном времени отключена")
        case ("Microsoft-Windows-Windows Defender/Operational", 5007): return String(localized: "Defender: изменена конфигурация \(short(f("New Value"), 120))")
        case ("Microsoft-Windows-WinRM/Operational", 6): return String(localized: "WinRM: создание сеанса \(short(f("connection"), 120))")
        case ("Microsoft-Windows-Bits-Client/Operational", 59): return String(localized: "BITS: задание \(f("name") ?? "?") → \(f("url") ?? "?")")
        default:
            return nil
        }
    }

    static func memberName(_ s: String?) -> String? {
        guard let s, s != "-" else { return nil }
        // "CN=Ivan Petrov,OU=…" → "Ivan Petrov"
        if s.hasPrefix("CN="), let comma = s.firstIndex(of: ",") { return String(s.dropFirst(3)[..<comma]) }
        return s
    }

    public static func logonTypeName(_ t: String) -> String? {
        switch t {
        case "0": "System"
        case "2": String(localized: "интерактивный")
        case "3": String(localized: "сетевой")
        case "4": String(localized: "пакетный")
        case "5": String(localized: "служба")
        case "7": String(localized: "разблокировка")
        case "8": String(localized: "сетевой, открытый пароль")
        case "9": String(localized: "новые учётные данные")
        case "10": "RDP"
        case "11": String(localized: "кэшированный интерактивный")
        case "12": String(localized: "кэшированный RDP")
        case "13": String(localized: "кэшированная разблокировка")
        default: nil
        }
    }

    /// NTSTATUS codes seen in 4625 / 4776 failures.
    public static func ntStatus(_ code: String) -> String? {
        switch code.lowercased() {
        case "0x0": String(localized: "успешно")
        case "0xc0000064": String(localized: "пользователь не существует")
        case "0xc000006a": String(localized: "неверный пароль")
        case "0xc000006d": String(localized: "неверное имя или пароль")
        case "0xc000006e": String(localized: "ограничение учётной записи")
        case "0xc000006f": String(localized: "вход вне разрешённого времени")
        case "0xc0000070": String(localized: "вход с неразрешённой рабочей станции")
        case "0xc0000071": String(localized: "срок действия пароля истёк")
        case "0xc0000072": String(localized: "учётная запись отключена")
        case "0xc0000133": String(localized: "рассинхронизация времени")
        case "0xc000015b": String(localized: "тип входа не разрешён")
        case "0xc0000193": String(localized: "срок действия учётной записи истёк")
        case "0xc0000224": String(localized: "требуется смена пароля")
        case "0xc0000234": String(localized: "учётная запись заблокирована")
        case "0xc0000413": String(localized: "межсетевой экран аутентификации")
        case "0xc00000dc": String(localized: "сервер в неверном состоянии")
        case "0xc0000371": String(localized: "локальное хранилище учётных данных недоступно")
        default: nil
        }
    }

    public static func kerberosError(_ code: String) -> String? {
        switch code.lowercased() {
        case "0x0": String(localized: "успешно")
        case "0x6": String(localized: "учётная запись не найдена")
        case "0x7": String(localized: "сервер не найден")
        case "0x12": String(localized: "учётная запись отключена или заблокирована")
        case "0x17": String(localized: "срок действия пароля истёк")
        case "0x18": String(localized: "неверный пароль")
        case "0x1b": String(localized: "сервер требует только Kerberos (U2U)")
        case "0x25": String(localized: "рассинхронизация времени")
        case "0x20": String(localized: "билет истёк")
        default: nil
        }
    }

    public static func encryptionType(_ code: String) -> String? {
        switch code.lowercased() {
        case "0x1": "DES-CBC-CRC"
        case "0x3": "DES-CBC-MD5"
        case "0x11": "AES128"
        case "0x12": "AES256"
        case "0x17": "RC4-HMAC"
        case "0x18": "RC4-HMAC-EXP"
        case "0xffffffff": String(localized: "ошибка")
        default: nil
        }
    }

    /// `%%NNNN` parameter messages (msobjs.dll) used by Security events.
    public static let parameterMessages: [String: String] = [
        "%%1537": "DELETE", "%%1538": "READ_CONTROL", "%%1539": "WRITE_DAC", "%%1540": "WRITE_OWNER",
        "%%1541": "SYNCHRONIZE", "%%1542": "ACCESS_SYS_SEC",
        "%%1832": "Identification", "%%1833": "Impersonation", "%%1840": "Delegation",
        "%%1842": "Yes", "%%1843": "No",
        "%%1936": String(localized: "Type 1 (полный токен, UAC отключён/встроенный администратор)"),
        "%%1937": String(localized: "Type 2 (повышенный токен)"),
        "%%1938": String(localized: "Type 3 (ограниченный токен)"),
        "%%4416": "ReadData (ListDirectory)", "%%4417": "WriteData (AddFile)",
        "%%4418": "AppendData (AddSubdirectory)", "%%4419": "ReadEA", "%%4420": "WriteEA",
        "%%4421": "Execute/Traverse", "%%4422": "DeleteChild", "%%4423": "ReadAttributes", "%%4424": "WriteAttributes",
    ]

    /// Replaces every `%%NNNN` token in `s` with its text, when known.
    public static func param(_ s: String) -> String {
        guard s.contains("%%") else { return s }
        var out = s
        for (code, text) in parameterMessages where out.contains(code) {
            out = out.replacingOccurrences(of: code, with: text)
        }
        return out
    }
}
