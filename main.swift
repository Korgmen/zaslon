// Zaslon: kill switch для приложений на macOS.
// Публичный IP не из белого списка -> защищённые процессы получают SIGSTOP,
// разрешённый IP вернулся за grace -> SIGCONT; не вернулся -> SIGTERM, затем SIGKILL.

import AppKit
import Darwin
import Network
import ServiceManagement
import SwiftUI

// MARK: - Конфиг

struct Config: Codable {
    var apps = ["/Claude.app/"]          // подстроки командной строки процесса, без учёта регистра
    var allowIPs: [String] = []          // IP или подсети (CIDR), IPv4 и IPv6
    var allowCountries: [String] = []    // коды стран ISO, например "NL"
    var grace = 20.0                     // сек заморозки до закрытия
    var closeTimeout = 5.0               // сек между SIGTERM и SIGKILL
    var checkInterval = 5.0              // сек между проверками, когда всё в порядке
    var minAgree = 2                     // сколько IP-сервисов должны назвать один адрес
    var checkIPv6 = true

    enum CodingKeys: String, CodingKey {
        case apps, grace
        case allowIPs = "allow_ips", allowCountries = "allow_countries"
        case closeTimeout = "close_timeout", checkInterval = "check_interval"
        case minAgree = "min_agree", checkIPv6 = "check_ipv6"
    }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Config()
        apps = try c.decodeIfPresent([String].self, forKey: .apps) ?? d.apps
        allowIPs = try c.decodeIfPresent([String].self, forKey: .allowIPs) ?? d.allowIPs
        allowCountries = try c.decodeIfPresent([String].self, forKey: .allowCountries) ?? d.allowCountries
        grace = try c.decodeIfPresent(Double.self, forKey: .grace) ?? d.grace
        closeTimeout = try c.decodeIfPresent(Double.self, forKey: .closeTimeout) ?? d.closeTimeout
        checkInterval = try c.decodeIfPresent(Double.self, forKey: .checkInterval) ?? d.checkInterval
        minAgree = try c.decodeIfPresent(Int.self, forKey: .minAgree) ?? d.minAgree
        checkIPv6 = try c.decodeIfPresent(Bool.self, forKey: .checkIPv6) ?? d.checkIPv6
    }
}

let configURL = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/Zaslon/config.json")

func configDate() -> Date? {
    (try? FileManager.default.attributesOfItem(atPath: configURL.path))?[.modificationDate] as? Date
}

// MARK: - Лог

let logURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Zaslon.log")

let logTimeFormat: DateFormatter = {
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    return f
}()

/// Строка в ~/Library/Logs/Zaslon.log; больше 1 МБ — старый файл уходит в Zaslon.log.1.
func zlog(_ msg: String) {
    let fm = FileManager.default
    if let size = (try? fm.attributesOfItem(atPath: logURL.path))?[.size] as? Int, size > 1_000_000 {
        let old = logURL.appendingPathExtension("1")
        try? fm.removeItem(at: old)
        try? fm.moveItem(at: logURL, to: old)
    }
    let data = Data("\(logTimeFormat.string(from: Date())) \(msg)\n".utf8)
    if let h = try? FileHandle(forWritingTo: logURL) {
        h.seekToEndOfFile()
        h.write(data)
        try? h.close()
    } else {
        try? data.write(to: logURL)
    }
}

/// Существенное в состоянии сети: есть ли сеть и какие интерфейсы (en0, utun4…) ею пользуются.
func pathSignature(_ p: NWPath) -> String {
    let ifs = Set(p.availableInterfaces.map(\.name)).sorted().joined(separator: ",")
    return "\(p.status) [\(ifs)]"
}

// MARK: - IP-адреса

func ipBytes(_ s: String) -> [UInt8]? {
    var v4 = in_addr(), v6 = in6_addr()
    if inet_pton(AF_INET, s, &v4) == 1 { return withUnsafeBytes(of: &v4) { Array($0) } }
    if inet_pton(AF_INET6, s, &v6) == 1 { return withUnsafeBytes(of: &v6) { Array($0) } }
    return nil
}

/// ip совпадает с правилом: точный адрес или подсеть "a.b.c.d/n", "2001:db8::/32".
func ipMatches(_ ip: String, _ rule: String) -> Bool {
    let parts = rule.trimmingCharacters(in: .whitespaces).split(separator: "/", maxSplits: 1).map(String.init)
    guard let first = parts.first, let a = ipBytes(ip), let b = ipBytes(first), a.count == b.count else { return false }
    let bits = parts.count == 2 ? (Int(parts[1]) ?? -1) : a.count * 8
    guard bits >= 0, bits <= a.count * 8 else { return false }
    for i in 0..<bits {
        let mask = UInt8(0x80) >> UInt8(i % 8)
        if a[i / 8] & mask != b[i / 8] & mask { return false }
    }
    return true
}

// MARK: - Сеть

let v4URLs = ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me",
              "https://checkip.amazonaws.com", "https://ipinfo.io/ip"]
let v6URLs = ["https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://v6.ident.me"]

/// Новая сессия на каждую проверку: соединения, открытые до смены сети, не переиспользуются.
func makeSession() -> URLSession {
    let c = URLSessionConfiguration.ephemeral
    c.timeoutIntervalForRequest = 4
    c.timeoutIntervalForResource = 5
    c.requestCachePolicy = .reloadIgnoringLocalCacheData
    c.urlCache = nil
    return URLSession(configuration: c)
}

func fetch(_ s: URLSession, _ url: String) async -> String? {
    guard let u = URL(string: url), let (data, resp) = try? await s.data(from: u),
          (resp as? HTTPURLResponse)?.statusCode == 200 else { return nil }
    return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}

/// Опрашивает сервисы параллельно; возвращает адрес, как только `need` сервисов назвали его,
/// остальные полученные адреса и сколько сервисов вообще ответило.
func fetchConsensus(_ s: URLSession, _ urls: [String], bytes: Int, need: Int) async -> (String?, [String], Int) {
    await withTaskGroup(of: String?.self) { g in
        for u in urls { g.addTask { await fetch(s, u) } }
        var counts: [String: Int] = [:]
        for await r in g {
            guard let r, ipBytes(r)?.count == bytes else { continue }
            counts[r, default: 0] += 1
            if counts[r]! >= need {
                g.cancelAll()
                return (r, counts.keys.filter { $0 != r }, counts.values.reduce(0, +))
            }
        }
        return (nil, Array(counts.keys), counts.values.reduce(0, +))
    }
}

/// Адрес DNS-резолвера, который реально ходит в интернет (whoami.akamai.net отвечает им).
func dnsResolverIP() async -> String? {
    await Task.detached {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo("whoami.akamai.net", nil, &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }
        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen, &buf, socklen_t(buf.count),
                          nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: buf)
    }.value
}

// MARK: - Защита

struct CheckResult {
    var v4: String?, v4Country: String?, v4Others: [String] = []
    var v4Partial: String?   // если адрес принят без нужного числа совпадений: почему
    var v6: String?, v6Country: String?
    var good = false
    var reason = ""
}

@MainActor final class Guard {
    enum State { case starting, ok, frozen(since: Date), closed, paused }

    var cfg = Config()
    var cfgDate: Date?
    var cfgError: String?
    var firstRun = false
    var state = State.starting
    var frozen: Set<pid_t> = []
    var last = CheckResult()
    var dnsIP: String?, dnsCountry: String?
    var lastCheckAt = Date.distantPast
    var onChange: () -> Void = {}

    private var countries: [String: String] = [:]
    private var checking = false, recheck = false
    private var netGen = 0
    private var pauseStart: Date?        // когда началась текущая пауза (для лога)
    private var lastTick = Date()
    private var pathSig: String?
    private var lastBadKey = ""          // чтобы не писать в лог одну и ту же неудачную проверку
    private var noAnswerStreak = 0       // проверок подряд, на которые не ответил ни один IPv4-сервис

    init(save: Bool) {
        if FileManager.default.fileExists(atPath: configURL.path) {
            reloadConfig()
        } else if save {
            firstRun = true
            saveConfig()
        }
    }

    // Конфиг

    func reloadConfig() {
        do {
            cfg = try JSONDecoder().decode(Config.self, from: Data(contentsOf: configURL))
            cfgError = nil
        } catch {
            cfgError = "ошибка в config.json, действуют прежние настройки"
        }
        cfgDate = configDate()
    }

    func saveConfig() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try? FileManager.default.createDirectory(at: configURL.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        try? enc.encode(cfg).write(to: configURL, options: .atomic)
        cfgDate = configDate()
    }

    func isAllowed(_ ip: String?, _ cc: String?) -> Bool {
        guard let ip else { return false }
        if cfg.allowIPs.contains(where: { ipMatches(ip, $0) }) { return true }
        if let cc, cfg.allowCountries.contains(where: { $0.uppercased() == cc }) { return true }
        return false
    }

    // Процессы

    func matchingPIDs() -> [pid_t] {
        let pats = cfg.apps.map { $0.lowercased() }.filter { !$0.isEmpty }
        guard !pats.isEmpty else { return [] }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/ps")
        p.arguments = ["-axww", "-o", "pid=,command="]
        let pipe = Pipe()
        p.standardOutput = pipe
        do { try p.run() } catch { return [] }
        // EOF = ps завершился. waitUntilExit не зовём: он крутит главный цикл,
        // и посреди tick() успевает отработать чужой код (например, разморозка).
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let me = getpid()
        return String(decoding: data, as: UTF8.self).split(separator: "\n").compactMap { line in
            let t = line.trimmingCharacters(in: .whitespaces)
            guard let sp = t.firstIndex(of: " "), let pid = pid_t(t[..<sp]), pid != me else { return nil }
            let cmd = t[sp...].lowercased()
            return pats.contains { cmd.contains($0) } ? pid : nil
        }
    }

    /// Возвращает, сколько процессов заморожено этим вызовом.
    @discardableResult
    func freezeAll() -> Int {
        var n = 0
        for p in matchingPIDs() where !frozen.contains(p) {
            if kill(p, SIGSTOP) == 0 { frozen.insert(p); n += 1 }
        }
        return n
    }

    func beginPause(_ why: String) {
        let n = freezeAll()
        state = .frozen(since: Date())
        pauseStart = Date()
        zlog("ПАУЗА: \(why); заморожено процессов: \(n)")
    }

    func resumeAll() {
        for p in frozen { kill(p, SIGCONT) }
        frozen.removeAll()
    }

    /// После падения прошлого запуска процессы могли остаться остановленными.
    func recoverStopped() {
        for p in matchingPIDs() { kill(p, SIGCONT) }
    }

    /// Сначала вежливо (SIGTERM + SIGCONT, чтобы процесс смог обработать сигнал и сохраниться),
    /// через closeTimeout принудительно тех, кто ещё жив.
    func closeAll() {
        let pids = Set(matchingPIDs()).union(frozen)
        for p in pids { kill(p, SIGTERM); kill(p, SIGCONT) }
        frozen.removeAll()
        closing = pids
        zlog("ЗАКРЫТИЕ: пауза \(Int(cfg.grace)) с истекла, SIGTERM процессам: \(pids.count)")
        DispatchQueue.main.asyncAfter(deadline: .now() + cfg.closeTimeout) { [weak self] in
            guard let self else { return }
            let alive = Set(self.matchingPIDs()).intersection(pids)
            for p in alive { kill(p, SIGKILL) }
            if !alive.isEmpty { zlog("ЗАКРЫТИЕ: SIGKILL не закрывшимся сами: \(alive.count)") }
            self.closing.subtract(pids)
        }
    }

    /// Процессы, которым отправлен SIGTERM и которые ещё могут сохраниться.
    var closing: Set<pid_t> = []

    /// После смены настроек: размораживаем то, что больше не под защитой, и перепроверяем.
    func configChanged() {
        let still = Set(matchingPIDs())
        let released = frozen.subtracting(still)
        for p in released { kill(p, SIGCONT) }
        frozen.formIntersection(still)
        zlog("настройки изменены: приложений \(cfg.apps.count), IP \(cfg.allowIPs.count), стран \(cfg.allowCountries.count)"
             + (released.isEmpty ? "" : "; разморожено снятых с защиты: \(released.count)"))
        Task { await check() }
    }

    // Цикл

    /// Раз в секунду.
    func tick() {
        // Во сне таймер стоит, а часы идут: пропуск больше 5 с значит, что Mac спал или процесс
        // был остановлен. Время сна не считается в паузу до закрытия, отсчёт начинается заново.
        let now = Date()
        let gap = now.timeIntervalSince(lastTick)
        lastTick = now
        if gap > 5, case .frozen = state {
            state = .frozen(since: now)
            zlog("пропуск \(Int(gap)) с (сон или приостановка): отсчёт паузы начат заново")
        }

        if configDate() != cfgDate {
            reloadConfig()
            configChanged()
        }
        switch state {
        case .paused:
            return
        case .frozen(let since):
            let n = freezeAll()  // новые запуски тоже замораживаем
            if n > 0 { zlog("заморожены новые процессы: \(n)") }
            if now.timeIntervalSince(since) >= cfg.grace {
                closeAll()
                state = .closed
            }
        case .closed:
            // Пока IP плохой, новые запуски убиваем; закрывающимся даём close_timeout.
            for p in matchingPIDs() where !closing.contains(p) {
                kill(p, SIGKILL)
                zlog("запуск заблокирован: pid \(p)")
            }
        default:
            break
        }
        let interval: Double
        if case .ok = state { interval = max(1, cfg.checkInterval) } else { interval = 2 }
        if !checking, Date().timeIntervalSince(lastCheckAt) >= interval { Task { await check() } }
        onChange()
    }

    /// Событие от NWPathMonitor. Пауза сразу — только если сеть пропала или сменились интерфейсы
    /// (например, исчез туннель VPN). Прочие события (DNS, роуминг Wi-Fi, флаги) — просто перепроверка.
    func pathChanged(_ sig: String) {
        let old = pathSig
        pathSig = sig
        guard let old else {
            zlog("сеть: \(sig)")
            return
        }
        guard old != sig else {
            zlog("сеть: событие без смены интерфейсов, перепроверка без паузы")
            Task { await check() }
            return
        }
        netGen += 1
        if case .ok = state {
            beginPause("сеть изменилась \(old) -> \(sig)")
            onChange()
        } else {
            zlog("сеть изменилась \(old) -> \(sig)")
        }
        Task { await check() }
    }

    func setPaused(_ paused: Bool) {
        if paused {
            resumeAll()
            state = .paused
            zlog("защита приостановлена вручную")
        } else {
            state = .starting
            zlog("защита возобновлена вручную")
            Task { await check() }
        }
        onChange()
    }

    func check() async {
        if checking { recheck = true; return }
        checking = true
        lastCheckAt = Date()
        let gen = netGen
        let r = await runCheck()
        checking = false
        // Сеть сменилась во время проверки: результат устарел.
        if gen != netGen {
            recheck = false
            Task { await check() }
            return
        }

        // Молчание всех сервисов — не утечка: трафик в этот момент никуда не идёт, а пропажу
        // сети или туннеля ловит pathChanged. Пауза, только если сервисы молчат две проверки подряд.
        let noAnswer = r.v4 == nil && r.v4Others.isEmpty
        noAnswerStreak = noAnswer ? noAnswerStreak + 1 : 0
        var running = false
        if case .ok = state { running = true }
        if case .starting = state { running = true }
        if noAnswer, noAnswerStreak < 2, running {
            zlog("нет ответа ни от одного IP-сервиса, повторная проверка без паузы")
            recheck = false
            Task { await check() }
            return
        }

        last = r
        if let p = r.v4Partial {
            zlog("медленная сеть: \(p); единственный адрес \(r.v4 ?? "—") принят, итог: \(r.good ? "разрешён" : r.reason)")
        }
        if !r.good {
            let key = "\(r.reason)|\(r.v4 ?? "")|\(r.v4Others)|\(r.v6 ?? "")"
            if key != lastBadKey {
                zlog("проверка не пройдена: \(r.reason); IPv4 \(r.v4 ?? "—") (\(r.v4Country ?? "?"))"
                     + (r.v4Others.isEmpty ? "" : ", другие ответы \(r.v4Others)")
                     + (r.v6.map { "; IPv6 \($0) (\(r.v6Country ?? "?"))" } ?? ""))
            }
            lastBadKey = key
        } else {
            lastBadKey = ""
        }
        apply(r)
        // Во время проверки поменялся конфиг или попросили проверить ещё раз.
        if recheck {
            recheck = false
            Task { await check() }
        }
        Task { await updateDNS() }
    }

    func runCheck() async -> CheckResult {
        let c = cfg
        let s = makeSession()
        defer { s.finishTasksAndInvalidate() }
        var r = CheckResult()

        async let v6 = c.checkIPv6 ? fetchConsensus(s, v6URLs, bytes: 16, need: 1) : (nil, [], 0)
        let need = min(max(1, c.minAgree), v4URLs.count)
        let answered: Int
        (r.v4, r.v4Others, answered) = await fetchConsensus(s, v4URLs, bytes: 4, need: need)
        // Ответили не все, но все назвали один адрес: несогласных нет, значит это не утечка,
        // а медленная сеть. Принимаем адрес и проверяем его по белому списку как обычно.
        if r.v4 == nil, r.v4Others.count == 1 {
            r.v4 = r.v4Others[0]
            r.v4Others = []
            r.v4Partial = "ответили \(answered) из \(v4URLs.count), нужно совпадение \(need)"
        }
        if let ip = r.v4 { r.v4Country = await country(ip, s) }

        if firstRun, let ip = r.v4 {
            r.v6 = await v6.0
            cfg.allowIPs.append(ip)
            if let ip6 = r.v6 { cfg.allowIPs.append(ip6) }
            firstRun = false
            saveConfig()
        }

        // Плохой IPv4: решение уже ясно, IPv6 не ждём.
        if r.v4 == nil {
            r.reason = r.v4Others.isEmpty ? "нет ответа от IP-сервисов" : "IP-сервисы не сошлись"
            return r
        }
        if !isAllowed(r.v4, r.v4Country) {
            r.reason = "IPv4 не в белом списке"
            return r
        }
        r.v6 = await v6.0
        if let ip = r.v6 { r.v6Country = await country(ip, s) }
        if r.v6 != nil && !isAllowed(r.v6, r.v6Country) {
            r.reason = "утечка IPv6"
        } else {
            r.good = true
        }
        return r
    }

    func updateDNS() async {
        guard let ip = await dnsResolverIP() else { dnsIP = nil; dnsCountry = nil; return }
        let s = makeSession()
        defer { s.finishTasksAndInvalidate() }
        dnsIP = ip
        dnsCountry = await country(ip, s)
    }

    func country(_ ip: String, _ s: URLSession) async -> String? {
        if let c = countries[ip] { return c }
        var cc = await fetch(s, "https://ipinfo.io/\(ip)/country")
        if cc?.count != 2, let j = await fetch(s, "https://api.country.is/\(ip)"),
           let o = try? JSONSerialization.jsonObject(with: Data(j.utf8)) as? [String: Any] {
            cc = o["country"] as? String
        }
        guard let cc, cc.count == 2 else { return nil }
        countries[ip] = cc.uppercased()
        return cc.uppercased()
    }

    func apply(_ r: CheckResult) {
        let ip = "\(r.v4 ?? "—") (\(r.v4Country ?? "?"))"
        switch (state, r.good) {
        case (.paused, _):
            break
        case (.ok, true):
            break
        case (.starting, true):
            state = .ok
            zlog("защита активна, IP \(ip)")
        case (_, true):
            let n = frozen.count
            resumeAll()
            state = .ok
            let dur = pauseStart.map { String(format: "%.1f", Date().timeIntervalSince($0)) } ?? "?"
            zlog("ВОЗОБНОВЛЕНО: IP \(ip) разрешён; с начала паузы прошло \(dur) с, разморожено процессов: \(n)")
            pauseStart = nil
        case (.ok, false), (.starting, false):
            beginPause(r.reason)
        default:
            break  // уже заморожено или закрыто
        }
        onChange()
    }

    var secondsLeft: Int {
        if case .frozen(let since) = state { return max(0, Int((cfg.grace - Date().timeIntervalSince(since)).rounded(.up))) }
        return 0
    }

    var statusText: String {
        switch state {
        case .starting: return "проверка…"
        case .ok: return "защита активна"
        case .frozen: return "приложения заморожены, закрытие через \(secondsLeft) с"
        case .closed: return "приложения закрыты, ждём разрешённый IP"
        case .paused: return "защита на паузе"
        }
    }
}

// MARK: - Автозапуск

/// Объект входа macOS для этого бандла. Регистрируется путь, откуда запущено приложение.
enum LoginItem {
    static var status: SMAppService.Status { SMAppService.mainApp.status }
    static var enabled: Bool { status == .enabled }

    /// Возвращает текст ошибки или nil.
    static func set(_ on: Bool) -> String? {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            zlog("автозапуск \(on ? "включён" : "выключен"), статус: \(status.rawValue)")
            return nil
        } catch {
            zlog("автозапуск: ошибка \(error.localizedDescription)")
            return error.localizedDescription
        }
    }
}

// MARK: - Настройки: модель

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespaces) }
}

func isValidIPRule(_ rule: String) -> Bool {
    let parts = rule.split(separator: "/", maxSplits: 1).map(String.init)
    guard let first = parts.first, let b = ipBytes(first) else { return false }
    guard parts.count == 2 else { return true }
    guard let bits = Int(parts[1]) else { return false }
    return (0...(b.count * 8)).contains(bits)
}

/// Приложение из /Applications и т. п. или запущенное; правило защиты: "/Имя.app/".
struct AppEntry: Identifiable {
    let id: String
    let name: String
    let url: URL
}

func installedApps() -> [AppEntry] {
    let fm = FileManager.default
    let dirs = ["/Applications", "/Applications/Utilities", "/System/Applications",
                "/System/Applications/Utilities", fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications").path]
    var urls = dirs.flatMap { (try? fm.contentsOfDirectory(at: URL(fileURLWithPath: $0), includingPropertiesForKeys: nil)) ?? [] }
    urls += NSWorkspace.shared.runningApplications.filter { $0.activationPolicy == .regular }.compactMap(\.bundleURL)
    var seen = Set<String>()
    var out: [AppEntry] = []
    for u in urls where u.pathExtension == "app" {
        let rule = "/\(u.lastPathComponent)/"
        guard seen.insert(rule.lowercased()).inserted else { continue }
        let name = (fm.displayName(atPath: u.path) as NSString).deletingPathExtension
        out.append(AppEntry(id: rule, name: name, url: u))
    }
    return out.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
}

/// Любое изменение сразу пишется в config.json и применяется.
@MainActor final class SettingsModel: ObservableObject {
    let g: Guard
    private var loading = false
    @Published var catalog: [AppEntry] = []
    @Published var loginStatus = LoginItem.status
    @Published var loginError: String?
    @Published var cfg: Config {
        didSet {
            guard !loading else { return }
            g.cfg = cfg
            g.saveConfig()
            g.configChanged()
        }
    }

    init(_ g: Guard) {
        self.g = g
        cfg = g.cfg
    }

    func reload() {
        loading = true
        cfg = g.cfg
        loading = false
        catalog = installedApps()
        loginStatus = LoginItem.status
    }

    func setLaunchAtLogin(_ on: Bool) {
        loginError = LoginItem.set(on)
        loginStatus = LoginItem.status
    }

    func entry(for rule: String) -> AppEntry? {
        catalog.first { $0.id.lowercased() == rule.lowercased() }
    }

    func isProtected(_ rule: String) -> Bool {
        cfg.apps.contains { $0.lowercased() == rule.lowercased() }
    }

    func setProtected(_ rule: String, _ on: Bool) {
        if on {
            if !isProtected(rule) { cfg.apps.append(rule) }
        } else {
            cfg.apps.removeAll { $0.lowercased() == rule.lowercased() }
        }
    }
}

// MARK: - Настройки: окна

struct AppIcon: View {
    let url: URL
    var body: some View {
        Image(nsImage: NSWorkspace.shared.icon(forFile: url.path)).resizable().frame(width: 18, height: 18)
    }
}

struct SettingsView: View {
    @ObservedObject var m: SettingsModel
    @State private var picking = false
    @State private var newRule = ""
    @State private var newIP = ""
    @State private var newCountry = ""

    var body: some View {
        Form {
            Section("Защищённые приложения") {
                if m.cfg.apps.isEmpty {
                    Text("Ничего не защищено").foregroundStyle(.secondary)
                }
                ForEach(m.cfg.apps, id: \.self) { rule in
                    HStack {
                        if let a = m.entry(for: rule) {
                            AppIcon(url: a.url)
                            Text(a.name)
                        } else {
                            Image(systemName: "terminal").frame(width: 18)
                            Text(rule).font(.body.monospaced())
                        }
                        Spacer()
                        removeButton { m.cfg.apps.removeAll { $0 == rule } }
                    }
                }
                Button("Выбрать приложения…") { picking = true }
                addRow("Своё правило: часть команды процесса", $newRule,
                       valid: !newRule.trimmed.isEmpty && !m.isProtected(newRule.trimmed)) {
                    m.cfg.apps.append(newRule.trimmed)
                }
            }

            Section("Разрешённые IP и подсети") {
                ForEach(m.cfg.allowIPs, id: \.self) { ip in
                    HStack {
                        Text(ip).font(.body.monospaced())
                        Spacer()
                        removeButton { m.cfg.allowIPs.removeAll { $0 == ip } }
                    }
                }
                addRow("Например 185.12.40.0/24", $newIP,
                       valid: isValidIPRule(newIP.trimmed) && !m.cfg.allowIPs.contains(newIP.trimmed)) {
                    m.cfg.allowIPs.append(newIP.trimmed)
                }
            }

            Section("Разрешённые страны") {
                ForEach(m.cfg.allowCountries, id: \.self) { cc in
                    HStack {
                        Text(cc)
                        Text(Locale.current.localizedString(forRegionCode: cc) ?? "").foregroundStyle(.secondary)
                        Spacer()
                        removeButton { m.cfg.allowCountries.removeAll { $0 == cc } }
                    }
                }
                let cc = newCountry.trimmed.uppercased()
                addRow("Код страны, например NL", $newCountry,
                       valid: cc.count == 2 && cc.allSatisfy(\.isLetter) && !m.cfg.allowCountries.contains(cc)) {
                    m.cfg.allowCountries.append(cc)
                }
            }

            Section("Запуск") {
                Toggle(isOn: Binding(get: { m.loginStatus == .enabled || m.loginStatus == .requiresApproval },
                                     set: { m.setLaunchAtLogin($0) })) {
                    Text("Запускать при входе в систему")
                    Text("Zaslon стартует сам после включения или перезагрузки Mac, и защита работает без ручного запуска.")
                }
                if m.loginStatus == .requiresApproval {
                    HStack {
                        Text("macOS ждёт разрешения в «Объектах входа»").foregroundStyle(.orange)
                        Spacer()
                        Button("Открыть настройки") { SMAppService.openSystemSettingsLoginItems() }
                    }
                }
                if let e = m.loginError {
                    Text("Не удалось изменить автозапуск: \(e)").foregroundStyle(.red)
                }
            }

            Section("Поведение") {
                Stepper(value: $m.cfg.grace, in: 5...600, step: 5) {
                    Text("Пауза до закрытия: \(Int(m.cfg.grace)) с")
                    Text("Сколько приложения стоят на паузе после того, как VPN отключился или IP сменился. Если VPN вернётся за это время, работа продолжится с того же места. Если нет, приложения закроются. Больше значение — меньше риск потерять работу при коротком сбое VPN.")
                }
                Stepper(value: $m.cfg.closeTimeout, in: 1...60) {
                    Text("Время на сохранение при закрытии: \(Int(m.cfg.closeTimeout)) с")
                    Text("Перед закрытием приложение просят завершиться самому, чтобы оно успело сохранить данные. Если за это время оно не закрылось, его закрывают принудительно.")
                }
                Stepper(value: $m.cfg.checkInterval, in: 2...60) {
                    Text("Интервал проверки: \(Int(m.cfg.checkInterval)) с")
                    Text("Как часто проверять IP, когда всё в порядке. При переподключении VPN или смене Wi-Fi проверка идёт сразу, не дожидаясь интервала. Меньше значение — быстрее реакция, но больше запросов к сервисам проверки.")
                }
                Stepper(value: $m.cfg.minAgree, in: 1...v4URLs.count) {
                    Text("Согласие сервисов: \(m.cfg.minAgree) из \(v4URLs.count)")
                    Text("IP узнаётся у \(v4URLs.count) независимых сервисов. Адрес считается настоящим, когда столько из них назвали один и тот же. Если из-за медленной сети ответили не все, но все назвали один адрес, он тоже принимается. Пауза — когда сервисы называют разные адреса или не отвечает ни один две проверки подряд.")
                }
                Toggle(isOn: $m.cfg.checkIPv6) {
                    Text("Следить за IPv6")
                    Text("Многие VPN защищают только IPv4, а IPv6 идёт в обход и выдаёт ваш настоящий адрес. Если включено, IPv6-адрес не из разрешённых считается утечкой и приложения ставятся на паузу. Если IPv6 у вас нет, настройка ни на что не влияет.")
                }
            }

            Section("О приложении") {
                HStack(spacing: 12) {
                    Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 40, height: 40)
                    VStack(alignment: .leading) {
                        Text("Zaslon").font(.headline)
                        Text("Версия \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—")")
                            .foregroundStyle(.secondary)
                    }
                }
                Text("Kill switch для отдельных приложений. Если VPN отключился, IP сменился или пропал интернет, выбранные приложения ставятся на паузу. Вернулся разрешённый IP — они продолжают работу. Не вернулся за отведённое время — закрываются.")
                Text("Защита работает на уровне приложений, а не всей сети: между сменой сети и паузой проходят доли секунды. Если важно, чтобы наружу не ушёл ни один пакет, включите ещё и kill switch в самом VPN-клиенте.")
                    .foregroundStyle(.secondary)
                Text("Для проверки адреса приложение обращается к api.ipify.org, icanhazip.com, ident.me, checkip.amazonaws.com и ipinfo.io, страну узнаёт у ipinfo.io и api.country.is, DNS-сервер — запросом whoami.akamai.net. Больше никуда данные не отправляются.")
                    .foregroundStyle(.secondary)
                LabeledContent("Файл настроек") {
                    Button("Показать в Finder") { NSWorkspace.shared.activateFileViewerSelecting([configURL]) }
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 480, minHeight: 560)
        .sheet(isPresented: $picking) { AppPicker(m: m) }
    }

    func removeButton(_ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: "minus.circle.fill").foregroundStyle(.secondary)
        }
        .buttonStyle(.borderless)
        .help("Убрать")
    }

    func addRow(_ prompt: String, _ text: Binding<String>, valid: Bool, add: @escaping () -> Void) -> some View {
        HStack {
            TextField("", text: text, prompt: Text(prompt)).labelsHidden()
                .onSubmit { if valid { add(); text.wrappedValue = "" } }
            Button("Добавить") { add(); text.wrappedValue = "" }.disabled(!valid)
        }
    }
}

struct AppPicker: View {
    @ObservedObject var m: SettingsModel
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""

    var filtered: [AppEntry] {
        query.trimmed.isEmpty ? m.catalog : m.catalog.filter { $0.name.localizedCaseInsensitiveContains(query.trimmed) }
    }

    var body: some View {
        VStack(spacing: 0) {
            TextField("Поиск", text: $query).textFieldStyle(.roundedBorder).padding(10)
            List(filtered) { a in
                Toggle(isOn: Binding(get: { m.isProtected(a.id) }, set: { m.setProtected(a.id, $0) })) {
                    HStack {
                        AppIcon(url: a.url)
                        Text(a.name)
                    }
                }
                .toggleStyle(.checkbox)
            }
            HStack {
                Text("Отмеченные замораживаются вместе со всеми своими процессами")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Готово") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(10)
        }
        .frame(width: 420, height: 520)
    }
}

// MARK: - Меню-бар

@MainActor final class App: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let g = Guard(save: true)
    var item: NSStatusItem!
    let monitor = NWPathMonitor()
    var timer: Timer?
    var signalSources: [DispatchSourceSignal] = []
    lazy var settings = SettingsModel(g)
    var settingsWindow: NSWindow?

    func applicationDidFinishLaunching(_ n: Notification) {
        installMainMenu()
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        g.onChange = { [weak self] in self?.render() }
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        zlog("=== Zaslon \(version) запущен; защищаются: \(g.cfg.apps), пауза до закрытия \(Int(g.cfg.grace)) с")
        g.recoverStopped()
        render()

        monitor.pathUpdateHandler = { [weak self] path in
            MainActor.assumeIsolated { self?.g.pathChanged(pathSignature(path)) }
        }
        monitor.start(queue: .main)

        let ws = NSWorkspace.shared.notificationCenter
        ws.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { _ in
            zlog("Mac засыпает")
        }
        ws.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            zlog("Mac проснулся")
            MainActor.assumeIsolated { self?.checkNow() }
        }

        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.g.tick() }
        }

        // kill/Ctrl+C: разморозить всё перед выходом.
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler { [weak self] in
                MainActor.assumeIsolated { self?.g.resumeAll() }
                zlog("=== Zaslon остановлен сигналом \(sig), всё разморожено")
                exit(0)
            }
            src.resume()
            signalSources.append(src)
        }

        Task { await g.check() }
    }

    func applicationWillTerminate(_ n: Notification) {
        g.resumeAll()
        zlog("=== Zaslon завершён, всё разморожено")
    }

    func render() {
        let r = g.last
        let (text, color): (String, NSColor) = switch g.state {
        case .starting: ("…", .secondaryLabelColor)
        case .ok: ("\(r.v4Country ?? "") \(r.v4 ?? "")", .systemGreen)
        case .frozen: ("\(g.secondsLeft) с", .systemOrange)
        case .closed: ("закрыто", .systemRed)
        case .paused: ("пауза", .secondaryLabelColor)
        }
        let font = NSFont.monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        let s = NSMutableAttributedString(string: "● ", attributes: [.foregroundColor: color, .font: font])
        s.append(NSAttributedString(string: text.trimmingCharacters(in: .whitespaces), attributes: [.font: font]))
        item.button?.attributedTitle = s
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let r = g.last

        func info(_ s: String) {
            let i = NSMenuItem(title: s, action: nil, keyEquivalent: "")
            i.isEnabled = false
            menu.addItem(i)
        }
        func action(_ title: String, _ sel: Selector, _ obj: Any? = nil, key: String = "") {
            let i = NSMenuItem(title: title, action: sel, keyEquivalent: key)
            i.target = self
            i.representedObject = obj
            menu.addItem(i)
        }
        func show(_ ip: String?, _ cc: String?, mark: Bool) -> String {
            guard let ip else { return "нет" }
            let tag = mark ? (g.isAllowed(ip, cc) ? "  разрешён" : "  НЕ разрешён") : ""
            return "\(ip) (\(cc ?? "?"))\(tag)"
        }

        info("Статус: \(g.statusText)")
        if !r.good, !r.reason.isEmpty { info("Причина: \(r.reason)") }
        if let e = g.cfgError { info("Конфиг: \(e)") }
        info("IPv4: \(show(r.v4, r.v4Country, mark: true))")
        if !r.v4Others.isEmpty { info("   другие ответы: \(r.v4Others.joined(separator: ", "))") }
        if g.cfg.checkIPv6 { info("IPv6: \(show(r.v6, r.v6Country, mark: true))") }
        info("DNS-резолвер: \(show(g.dnsIP, g.dnsCountry, mark: false))")
        let pids = g.matchingPIDs().count
        info("Процессов под защитой: \(pids)" + (g.frozen.isEmpty ? "" : ", заморожено: \(g.frozen.count)"))

        menu.addItem(.separator())
        action("Проверить сейчас", #selector(checkNow), key: "r")
        for (ip, cc) in [(r.v4, r.v4Country), (r.v6, r.v6Country)] {
            guard let ip, !g.isAllowed(ip, cc) else { continue }
            action("Разрешить IP \(ip)", #selector(allowIP), ip)
            if let cc { action("Разрешить страну \(cc)", #selector(allowCountry), cc) }
        }
        if case .paused = g.state {
            action("Возобновить защиту", #selector(togglePause))
        } else {
            action("Приостановить защиту", #selector(togglePause))
        }
        action("Запускать при входе в систему", #selector(toggleLaunchAtLogin))
        menu.items.last?.state = LoginItem.status == .notRegistered || LoginItem.status == .notFound ? .off : .on
        action("Настройки…", #selector(openSettings), key: ",")
        action("Открыть лог", #selector(openLog), key: "l")
        menu.addItem(.separator())
        action("Выход", #selector(quit), key: "q")
    }

    @objc func checkNow() { Task { await g.check() } }

    @objc func allowIP(_ sender: NSMenuItem) {
        guard let ip = sender.representedObject as? String else { return }
        g.cfg.allowIPs.append(ip)
        g.saveConfig()
        settings.reload()
        checkNow()
    }

    @objc func allowCountry(_ sender: NSMenuItem) {
        guard let cc = sender.representedObject as? String else { return }
        g.cfg.allowCountries.append(cc)
        g.saveConfig()
        settings.reload()
        checkNow()
    }

    @objc func toggleLaunchAtLogin() {
        settings.setLaunchAtLogin(!LoginItem.enabled && LoginItem.status != .requiresApproval)
        if LoginItem.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
    }

    @objc func togglePause() {
        if case .paused = g.state { g.setPaused(false) } else { g.setPaused(true) }
    }

    /// Лог в «Консоли»: она подхватывает новые строки на лету.
    @objc func openLog() {
        if !FileManager.default.fileExists(atPath: logURL.path) { zlog("лог создан") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        p.arguments = ["-a", "Console", logURL.path]
        try? p.run()
    }

    @objc func openSettings() {
        settings.reload()
        if settingsWindow == nil {
            let w = NSWindow(contentViewController: NSHostingController(rootView: SettingsView(m: settings)))
            w.title = "Zaslon: настройки"
            w.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            w.isReleasedWhenClosed = false
            w.center()
            settingsWindow = w
        }
        NSApp.activate(ignoringOtherApps: true)
        settingsWindow?.makeKeyAndOrderFront(nil)
    }

    /// Без главного меню в приложении-агенте не работают ⌘C/⌘V/⌘W в окне настроек.
    func installMainMenu() {
        let main = NSMenu()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Закрыть окно", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        appMenu.addItem(withTitle: "Выход", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let edit = NSMenu(title: "Правка")
        edit.addItem(withTitle: "Отменить", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "Повторить", action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(.separator())
        edit.addItem(withTitle: "Вырезать", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Копировать", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Вставить", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Выбрать всё", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        for sub in [appMenu, edit] {
            let i = NSMenuItem()
            i.submenu = sub
            main.addItem(i)
        }
        NSApp.mainMenu = main
    }

    @objc func quit() {
        g.resumeAll()
        NSApp.terminate(nil)
    }
}

// MARK: - Запуск

if CommandLine.arguments.contains("--check") {
    // Только проверка: ничего не замораживает и не пишет конфиг.
    Task { @MainActor in
        let g = Guard(save: false)
        let r = await g.runCheck()
        let dns = await dnsResolverIP()
        @MainActor func line(_ ip: String?, _ cc: String?) -> String {
            guard let ip else { return "нет" }
            return "\(ip) (\(cc ?? "?")) " + (g.isAllowed(ip, cc) ? "разрешён" : "НЕ разрешён")
        }
        print("Конфиг: \(configURL.path)" + (g.cfgError.map { " (\($0))" } ?? ""))
        print("IPv4:  \(line(r.v4, r.v4Country))" + (r.v4Others.isEmpty ? "" : "; другие ответы: \(r.v4Others)"))
        print("IPv6:  \(line(r.v6, r.v6Country))")
        print("DNS:   \(dns ?? "нет")")
        print("Итог:  " + (r.good ? "OK" : "ЗАМОРОЗКА (\(r.reason))"))
        print("Процессы под защитой: \(g.matchingPIDs())")
        exit(r.good ? 0 : 1)
    }
    RunLoop.main.run()
} else {
    MainActor.assumeIsolated {
        let app = NSApplication.shared
        let delegate = App()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }
}
