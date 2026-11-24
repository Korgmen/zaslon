// Состояния защиты и цикл проверок. Весь код выполняется в потоке UI: продолжения await возвращаются в него же.

using System.Net.Sockets;
using System.Text.Json;

namespace Zaslon;

sealed class CheckResult
{
    public string? V4, V4Country;
    public List<string> V4Others = [];
    /// Если адрес принят без нужного числа совпадений: почему.
    public string? V4Partial;
    public string? V6, V6Country;
    public bool Good;
    public string Reason = "";
}

enum State { Starting, Ok, Blocked, Paused }

sealed class Guard
{
    public Config Cfg = new();
    public string? CfgError;
    public State State = State.Starting;
    public CheckResult Last = new();
    public string? DnsIP, DnsCountry;
    /// Брандмауэр выключен или его состояние не прочиталось: блокировка может не действовать.
    public string? FirewallWarning;
    public Action OnChange = () => { };
    public Action OnConfigReloaded = () => { };

    DateTime cfgDate;
    bool firstRun;
    readonly Dictionary<string, string> countries = [];
    bool checking, recheck;
    int netGen;
    DateTime? blockStart;
    DateTime lastCheckAt = DateTime.MinValue;
    string? pathSig;
    /// Чтобы не писать в лог одну и ту же неудачную проверку.
    string lastBadKey = "";
    /// Проверок подряд, на которые не ответил ни один IPv4-сервис.
    int noAnswerStreak;
    /// Защищённые exe, замеченные за время работы: при блокировке правило получают и те, что сейчас не запущены.
    readonly HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

    public Guard(bool save)
    {
        if (File.Exists(Paths.Config))
        {
            ReloadConfig();
        }
        else if (save)
        {
            firstRun = true;
            SaveConfig();
        }
    }

    // Конфиг

    public void ReloadConfig()
    {
        try
        {
            Cfg = Config.Load();
            CfgError = null;
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            CfgError = "ошибка в config.json, действуют прежние настройки";
        }
        cfgDate = Paths.ConfigDate();
    }

    public void SaveConfig()
    {
        try
        {
            Cfg.Save();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            Log.Write($"не удалось сохранить config.json: {e.Message}");
        }
        cfgDate = Paths.ConfigDate();
    }

    public bool IsAllowed(string? ip, string? cc)
    {
        if (ip == null) return false;
        if (Cfg.AllowIPs.Any(r => Ip.Matches(ip, r))) return true;
        return cc != null && Cfg.AllowCountries.Any(c => c.Equals(cc, StringComparison.OrdinalIgnoreCase));
    }

    // Процессы и правила

    public List<(int Pid, string Path)> Matching() => Procs.Matching(Cfg.Apps);

    bool IsProtected(string path) => Procs.IsProtected(path, Cfg.Apps);

    void Learn(List<(int Pid, string Path)> procs)
    {
        foreach (var p in procs) seen.Add(p.Path);
    }

    /// Блокирует сеть защищённым exe и рвёт их IPv4-соединения. Возвращает, сколько exe заблокировано этим вызовом.
    int BlockAll()
    {
        var procs = Matching();
        Learn(procs);
        var added = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in seen.Where(p => !Firewall.IsBlocked(p)).ToList())
        {
            try
            {
                Firewall.Block(path);
                added.Add(path);
            }
            catch (Exception e)
            {
                Log.Write($"не удалось заблокировать {path}: {e.Message}");
            }
        }
        if (added.Count > 0)
        {
            var reset = Firewall.ResetTcp(procs.Where(p => added.Contains(p.Path)).Select(p => p.Pid).ToHashSet());
            if (reset > 0) Log.Write($"разорвано TCP-соединений: {reset}");
        }
        return added.Count;
    }

    void BeginBlock(string why)
    {
        var n = BlockAll();
        State = State.Blocked;
        blockStart = DateTime.Now;
        FirewallWarning = Firewall.Warning();
        Log.Write($"БЛОКИРОВКА: {why}; новых правил для программ: {n}, всего заблокировано: {Firewall.Paths.Count}"
                  + (FirewallWarning != null ? $"; ВНИМАНИЕ: {FirewallWarning}" : ""));
    }

    /// Снимает правила с exe, которые больше не под защитой. Возвращает их число.
    public int ReleaseUnprotected()
    {
        seen.RemoveWhere(p => !IsProtected(p));
        var released = Firewall.Paths.Where(p => !IsProtected(p)).ToList();
        foreach (var p in released) Firewall.Unblock(p);
        return released.Count;
    }

    /// После смены настроек: разблокируем то, что больше не под защитой, и перепроверяем.
    public void ConfigChanged()
    {
        var released = ReleaseUnprotected();
        Log.Write($"настройки изменены: приложений {Cfg.Apps.Count}, IP {Cfg.AllowIPs.Count}, стран {Cfg.AllowCountries.Count}"
                  + (released == 0 ? "" : $"; разблокировано снятых с защиты: {released}"));
        OnChange();
        _ = Check();
    }

    // Цикл

    /// Раз в секунду.
    public void Tick()
    {
        if (Paths.ConfigDate() != cfgDate)
        {
            ReloadConfig();
            OnConfigReloaded();
            ConfigChanged();
        }
        switch (State)
        {
            case State.Paused:
                return;
            case State.Blocked:
                var n = BlockAll();  // новые запуски тоже блокируем
                if (n > 0) Log.Write($"заблокированы новые программы: {n}");
                break;
        }
        var interval = State == State.Ok ? Math.Max(1, Cfg.CheckInterval) : 2;
        if (!checking && (DateTime.UtcNow - lastCheckAt).TotalSeconds >= interval) _ = Check();
        OnChange();
    }

    /// Событие смены сети. Блокировка сразу — только если сеть пропала или сменились интерфейсы
    /// (например, исчез адаптер VPN). Прочие события (адреса, DHCP) — просто перепроверка.
    public void PathChanged(string sig)
    {
        var old = pathSig;
        pathSig = sig;
        if (old == null)
        {
            Log.Write($"сеть: {sig}");
            return;
        }
        if (old == sig)
        {
            Log.Write("сеть: событие без смены интерфейсов, перепроверка без блокировки");
            _ = Check();
            return;
        }
        netGen++;
        if (State == State.Ok)
        {
            BeginBlock($"сеть изменилась {old} -> {sig}");
            OnChange();
        }
        else
        {
            Log.Write($"сеть изменилась {old} -> {sig}");
        }
        _ = Check();
    }

    public void SetPaused(bool paused)
    {
        if (paused)
        {
            Firewall.UnblockAll();
            State = State.Paused;
            Log.Write("защита приостановлена вручную");
        }
        else
        {
            State = State.Starting;
            Log.Write("защита возобновлена вручную");
            _ = Check();
        }
        OnChange();
    }

    public async Task Check()
    {
        if (checking)
        {
            recheck = true;
            return;
        }
        checking = true;
        lastCheckAt = DateTime.UtcNow;
        var gen = netGen;
        CheckResult r;
        try
        {
            r = await RunCheck();
        }
        finally
        {
            checking = false;
        }
        // Сеть сменилась во время проверки: результат устарел.
        if (gen != netGen)
        {
            recheck = false;
            _ = Check();
            return;
        }

        // Молчание всех сервисов — не утечка: трафик в этот момент никуда не идёт, а пропажу
        // сети или адаптера VPN ловит PathChanged. Блокировка, только если сервисы молчат две проверки подряд.
        var noAnswer = r.V4 == null && r.V4Others.Count == 0;
        noAnswerStreak = noAnswer ? noAnswerStreak + 1 : 0;
        if (noAnswer && noAnswerStreak < 2 && State is State.Ok or State.Starting)
        {
            Log.Write("нет ответа ни от одного IP-сервиса, повторная проверка без блокировки");
            recheck = false;
            _ = Check();
            return;
        }

        Last = r;
        if (r.V4Partial != null)
            Log.Write($"медленная сеть: {r.V4Partial}; единственный адрес {r.V4 ?? "—"} принят, итог: {(r.Good ? "разрешён" : r.Reason)}");
        if (!r.Good)
        {
            var key = $"{r.Reason}|{r.V4}|{string.Join(",", r.V4Others)}|{r.V6}";
            if (key != lastBadKey)
            {
                Log.Write($"проверка не пройдена: {r.Reason}; IPv4 {r.V4 ?? "—"} ({r.V4Country ?? "?"})"
                          + (r.V4Others.Count == 0 ? "" : $", другие ответы [{string.Join(", ", r.V4Others)}]")
                          + (r.V6 != null ? $"; IPv6 {r.V6} ({r.V6Country ?? "?"})" : ""));
            }
            lastBadKey = key;
        }
        else
        {
            lastBadKey = "";
        }
        Apply(r);
        // Во время проверки поменялся конфиг или попросили проверить ещё раз.
        if (recheck)
        {
            recheck = false;
            _ = Check();
        }
        _ = UpdateDns();
    }

    public async Task<CheckResult> RunCheck()
    {
        var c = Cfg;
        using var http = Net.MakeClient();
        var r = new CheckResult();

        var v6 = c.CheckIPv6
            ? Net.Consensus(http, Net.V6Urls, AddressFamily.InterNetworkV6, 1)
            : Task.FromResult<(string?, List<string>, int)>((null, [], 0));
        var need = Math.Min(Math.Max(1, c.MinAgree), Net.V4Urls.Length);
        (r.V4, r.V4Others, var answered) = await Net.Consensus(http, Net.V4Urls, AddressFamily.InterNetwork, need);
        // Ответили не все, но все назвали один адрес: несогласных нет, значит это не утечка,
        // а медленная сеть. Принимаем адрес и проверяем его по белому списку как обычно.
        if (r.V4 == null && r.V4Others.Count == 1)
        {
            r.V4 = r.V4Others[0];
            r.V4Others = [];
            r.V4Partial = $"ответили {answered} из {Net.V4Urls.Length}, нужно совпадение {need}";
        }
        if (r.V4 != null) r.V4Country = await Country(r.V4, http);

        if (firstRun && r.V4 != null)
        {
            r.V6 = (await v6).Item1;
            Cfg.AllowIPs.Add(r.V4);
            if (r.V6 != null) Cfg.AllowIPs.Add(r.V6);
            firstRun = false;
            SaveConfig();
        }

        // Плохой IPv4: решение уже ясно, IPv6 не ждём.
        if (r.V4 == null)
        {
            r.Reason = r.V4Others.Count == 0 ? "нет ответа от IP-сервисов" : "IP-сервисы не сошлись";
            return r;
        }
        if (!IsAllowed(r.V4, r.V4Country))
        {
            r.Reason = "IPv4 не в белом списке";
            return r;
        }
        r.V6 = (await v6).Item1;
        if (r.V6 != null) r.V6Country = await Country(r.V6, http);
        if (r.V6 != null && !IsAllowed(r.V6, r.V6Country))
            r.Reason = "утечка IPv6";
        else
            r.Good = true;
        return r;
    }

    async Task UpdateDns()
    {
        var ip = await Net.DnsResolverIP();
        if (ip == null)
        {
            DnsIP = DnsCountry = null;
            return;
        }
        using var http = Net.MakeClient();
        DnsIP = ip;
        DnsCountry = await Country(ip, http);
    }

    async Task<string?> Country(string ip, HttpClient http)
    {
        if (countries.TryGetValue(ip, out var cached)) return cached;
        var cc = await Net.Fetch(http, $"https://ipinfo.io/{ip}/country");
        if (cc?.Length != 2 && await Net.Fetch(http, $"https://api.country.is/{ip}") is { } j)
        {
            try
            {
                using var doc = JsonDocument.Parse(j);
                cc = doc.RootElement.TryGetProperty("country", out var v) ? v.GetString() : null;
            }
            catch (JsonException) { }
        }
        if (cc?.Length != 2) return null;
        cc = cc.ToUpperInvariant();
        countries[ip] = cc;
        return cc;
    }

    void Apply(CheckResult r)
    {
        var ip = $"{r.V4 ?? "—"} ({r.V4Country ?? "?"})";
        switch (State, r.Good)
        {
            case (State.Paused, _):
                break;
            case (State.Ok, true):
                Learn(Matching());
                break;
            case (State.Starting, true):
                // Правила, оставшиеся от прошлого запуска, действуют до первой удачной проверки.
                var left = Firewall.UnblockAll();
                State = State.Ok;
                Learn(Matching());
                Log.Write($"защита активна, IP {ip}" + (left > 0 ? $"; снято правил прошлого запуска: {left}" : ""));
                break;
            case (_, true):
                var n = Firewall.UnblockAll();
                State = State.Ok;
                var dur = blockStart is { } s ? $"{(DateTime.Now - s).TotalSeconds:0.0}" : "?";
                Log.Write($"ВОЗОБНОВЛЕНО: IP {ip} разрешён; с начала блокировки прошло {dur} с, разблокировано программ: {n}");
                blockStart = null;
                break;
            case (State.Ok or State.Starting, false):
                BeginBlock(r.Reason);
                break;
            default:
                break;  // уже заблокировано
        }
        OnChange();
    }

    public string StatusText => State switch
    {
        State.Starting => "проверка…",
        State.Ok => "защита активна",
        State.Blocked => "сеть приложений заблокирована, ждём разрешённый IP",
        _ => "защита на паузе",
    };
}
