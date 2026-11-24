// Конфиг, лог, IP-адреса и запросы к IP-сервисам. Правила те же, что в main.swift (macOS).

using System.Net;
using System.Net.Sockets;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Zaslon;

sealed class Config
{
    /// Подстроки полного пути exe, без учёта регистра.
    [JsonPropertyName("apps")] public List<string> Apps { get; set; } = [@"\claude.exe"];
    /// IP или подсети (CIDR), IPv4 и IPv6.
    [JsonPropertyName("allow_ips")] public List<string> AllowIPs { get; set; } = [];
    /// Коды стран ISO, например "NL".
    [JsonPropertyName("allow_countries")] public List<string> AllowCountries { get; set; } = [];
    /// Секунд между проверками, когда всё в порядке.
    [JsonPropertyName("check_interval")] public double CheckInterval { get; set; } = 5;
    /// Сколько IP-сервисов должны назвать один адрес.
    [JsonPropertyName("min_agree")] public int MinAgree { get; set; } = 2;
    [JsonPropertyName("check_ipv6")] public bool CheckIPv6 { get; set; } = true;

    static readonly JsonSerializerOptions json = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        RespectNullableAnnotations = true,
    };

    public static Config Load() =>
        JsonSerializer.Deserialize<Config>(File.ReadAllText(Paths.Config), json) ?? throw new JsonException("пустой файл");

    public void Save()
    {
        Directory.CreateDirectory(Paths.Dir);
        var tmp = Paths.Config + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, json));
        File.Move(tmp, Paths.Config, true);
    }
}

static class Paths
{
    public static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Zaslon");
    public static readonly string Config = Path.Combine(Dir, "config.json");
    public static readonly string Log =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Zaslon", "Zaslon.log");

    public static DateTime ConfigDate() => File.GetLastWriteTimeUtc(Config);
}

static class Log
{
    static readonly Lock gate = new();

    /// Строка в %LOCALAPPDATA%\Zaslon\Zaslon.log; больше 1 МБ — старый файл уходит в Zaslon.log.1.
    public static void Write(string msg)
    {
        lock (gate)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Paths.Log)!);
                var fi = new FileInfo(Paths.Log);
                if (fi.Exists && fi.Length > 1_000_000) File.Move(Paths.Log, Paths.Log + ".1", true);
                File.AppendAllText(Paths.Log, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {msg}\r\n");
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}

static class Ip
{
    /// Строгая запись адреса: IPAddress.TryParse принимает и "1" или "1.2" как IPv4.
    public static IPAddress? Parse(string s)
    {
        if (!IPAddress.TryParse(s, out var a)) return null;
        return a.AddressFamily switch
        {
            AddressFamily.InterNetwork when s.Split('.').Length == 4 => a,
            AddressFamily.InterNetworkV6 when !s.Contains('%') => a,
            _ => null,
        };
    }

    /// ip совпадает с правилом: точный адрес или подсеть "a.b.c.d/n", "2001:db8::/32".
    public static bool Matches(string ip, string rule)
    {
        var parts = rule.Trim().Split('/', 2);
        var a = Parse(ip)?.GetAddressBytes();
        var b = Parse(parts[0])?.GetAddressBytes();
        if (a == null || b == null || a.Length != b.Length) return false;
        var bits = a.Length * 8;
        if (parts.Length == 2 && !int.TryParse(parts[1], out bits)) return false;
        if (bits < 0 || bits > a.Length * 8) return false;
        for (var i = 0; i < bits; i++)
        {
            var mask = 0x80 >> (i % 8);
            if ((a[i / 8] & mask) != (b[i / 8] & mask)) return false;
        }
        return true;
    }

    public static bool IsValidRule(string rule)
    {
        var parts = rule.Split('/', 2);
        var b = Parse(parts[0]);
        if (b == null) return false;
        if (parts.Length == 1) return true;
        return int.TryParse(parts[1], out var bits) && bits >= 0 && bits <= b.GetAddressBytes().Length * 8;
    }
}

static class Net
{
    public static readonly string[] V4Urls = ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me",
                                              "https://checkip.amazonaws.com", "https://ipinfo.io/ip"];
    public static readonly string[] V6Urls = ["https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://v6.ident.me"];

    /// Новый клиент на каждую проверку: соединения, открытые до смены сети, не переиспользуются.
    public static HttpClient MakeClient() =>
        new(new SocketsHttpHandler { UseCookies = false, ConnectTimeout = TimeSpan.FromSeconds(4) })
        {
            Timeout = TimeSpan.FromSeconds(5),
        };

    public static async Task<string?> Fetch(HttpClient c, string url, CancellationToken ct = default)
    {
        try
        {
            using var r = await c.GetAsync(url, ct);
            if (r.StatusCode != HttpStatusCode.OK) return null;
            return (await r.Content.ReadAsStringAsync(ct)).Trim();
        }
        catch (HttpRequestException) { return null; }
        catch (OperationCanceledException) { return null; }
    }

    /// Опрашивает сервисы параллельно; возвращает адрес, как только `need` сервисов назвали его,
    /// остальные полученные адреса и сколько сервисов вообще ответило.
    public static async Task<(string? Ip, List<string> Others, int Answered)> Consensus(
        HttpClient c, string[] urls, AddressFamily family, int need)
    {
        using var cts = new CancellationTokenSource();
        var pending = urls.Select(u => Fetch(c, u, cts.Token)).ToList();
        var counts = new Dictionary<string, int>();
        while (pending.Count > 0)
        {
            var t = await Task.WhenAny(pending);
            pending.Remove(t);
            var a = await t is { } s ? Ip.Parse(s) : null;
            if (a == null || a.AddressFamily != family) continue;
            var ip = a.ToString();
            counts[ip] = counts.GetValueOrDefault(ip) + 1;
            if (counts[ip] >= need)
            {
                cts.Cancel();
                return (ip, counts.Keys.Where(k => k != ip).ToList(), counts.Values.Sum());
            }
        }
        return (null, counts.Keys.ToList(), counts.Values.Sum());
    }

    /// Адрес DNS-резолвера, который реально ходит в интернет (whoami.akamai.net отвечает им).
    public static async Task<string?> DnsResolverIP()
    {
        try
        {
            var a = await Dns.GetHostAddressesAsync("whoami.akamai.net");
            return a.FirstOrDefault()?.ToString();
        }
        catch (SocketException) { return null; }
    }
}
