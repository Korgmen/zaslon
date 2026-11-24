// Процессы, правила брандмауэра Windows и разрыв TCP-соединений. Нужны права администратора.

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Zaslon;

static class Procs
{
    const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, [Out] char[] name, ref uint size);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    public static string? ImagePath(int pid)
    {
        var h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var buf = new char[1024];
            var size = (uint)buf.Length;
            return QueryFullProcessImageNameW(h, 0, buf, ref size) ? new string(buf, 0, (int)size) : null;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    static string[] Patterns(IEnumerable<string> apps) =>
        apps.Select(a => a.Trim().Replace('/', '\\').ToLowerInvariant()).Where(a => a.Length > 0).ToArray();

    public static bool IsProtected(string path, IEnumerable<string> apps)
    {
        var l = path.ToLowerInvariant();
        return Patterns(apps).Any(l.Contains);
    }

    /// Процессы всех пользователей, чей путь к exe содержит одно из правил.
    public static List<(int Pid, string Path)> Matching(IEnumerable<string> apps)
    {
        var pats = Patterns(apps);
        var res = new List<(int, string)>();
        if (pats.Length == 0) return res;
        var me = Environment.ProcessId;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id == me || p.Id <= 4) continue;
                var path = ImagePath(p.Id);
                if (path != null && pats.Any(path.ToLowerInvariant().Contains)) res.Add((p.Id, path));
            }
        }
        return res;
    }
}

static class Firewall
{
    const string Group = "Zaslon";
    const int ActionBlock = 0, DirIn = 1, DirOut = 2, ProfilesAll = 0x7FFFFFFF;

    /// Заблокированный exe -> имена его правил.
    static readonly Dictionary<string, List<string>> rules = new(StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyCollection<string> Paths => rules.Keys;

    public static bool IsBlocked(string path) => rules.ContainsKey(path);

    static dynamic Com(string progId) =>
        Activator.CreateInstance(Type.GetTypeFromProgID(progId, true)!)!;

    /// Правила группы Zaslon, оставшиеся после сбоя или выключения Windows во время блокировки.
    /// Остаются в силе, пока первая проверка не решит, снимать ли их.
    public static int LoadExisting()
    {
        dynamic policy = Com("HNetCfg.FwPolicy2");
        foreach (dynamic r in policy.Rules)
        {
            if ((string?)r.Grouping != Group) continue;
            string path = (string?)r.ApplicationName ?? "";
            if (!rules.TryGetValue(path, out var names)) rules[path] = names = [];
            names.Add((string)r.Name);
        }
        return rules.Count;
    }

    /// Запрещает exe входящие и исходящие соединения во всех профилях сети. Loopback брандмауэр не фильтрует.
    public static void Block(string path)
    {
        dynamic policy = Com("HNetCfg.FwPolicy2");
        var names = new List<string>();
        try
        {
            foreach (var (dir, tag) in new[] { (DirOut, "исходящие"), (DirIn, "входящие") })
            {
                dynamic r = Com("HNetCfg.FWRule");
                var name = $"Zaslon ({tag}): {path}";
                r.Name = name;
                r.Description = "Kill switch Zaslon: сеть заблокирована, пока не вернётся разрешённый IP";
                r.Grouping = Group;
                r.ApplicationName = path;
                r.Direction = dir;
                r.Action = ActionBlock;
                r.Profiles = ProfilesAll;
                r.Enabled = true;
                policy.Rules.Add(r);
                names.Add(name);
            }
        }
        catch
        {
            foreach (var n in names) policy.Rules.Remove(n);
            throw;
        }
        rules[path] = names;
    }

    public static void Unblock(string path)
    {
        if (!rules.Remove(path, out var names)) return;
        try
        {
            dynamic policy = Com("HNetCfg.FwPolicy2");
            foreach (var n in names) policy.Rules.Remove(n);
        }
        catch (Exception e)
        {
            Log.Write($"не удалось снять правило для {path}: {e.Message}");
        }
    }

    /// Возвращает, со скольких exe снята блокировка.
    public static int UnblockAll()
    {
        var paths = rules.Keys.ToList();
        foreach (var p in paths) Unblock(p);
        return paths.Count;
    }

    /// Текст предупреждения, если брандмауэр Windows выключен в активном профиле сети: тогда правила не действуют.
    public static string? Warning()
    {
        try
        {
            dynamic policy = Com("HNetCfg.FwPolicy2");
            int current = policy.CurrentProfileTypes;
            foreach (var (bit, name) in new[] { (1, "домен"), (2, "частная сеть"), (4, "общественная сеть") })
            {
                if ((current & bit) != 0 && !(bool)policy.FirewallEnabled[bit])
                    return $"брандмауэр Windows выключен для профиля «{name}», блокировка не действует";
            }
            return null;
        }
        catch (Exception e)
        {
            Log.Write($"не удалось прочитать состояние брандмауэра: {e.Message}");
            return "не удалось проверить, включён ли брандмауэр Windows";
        }
    }

    // Разрыв соединений

    const int AfInet = 2, TcpTableOwnerPidAll = 5, ErrorInsufficientBuffer = 122;
    const uint StateEstablished = 5, StateDeleteTcb = 12;

    [StructLayout(LayoutKind.Sequential)]
    struct TcpRowOwnerPid { public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid; }

    [StructLayout(LayoutKind.Sequential)]
    struct TcpRow { public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort; }

    [DllImport("iphlpapi.dll")]
    static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll")]
    static extern uint SetTcpEntry(ref TcpRow row);

    /// Рвёт установленные IPv4-соединения процессов, кроме loopback: новое правило брандмауэра
    /// гарантированно действует на новые соединения. Для IPv6 у Windows такого API нет.
    public static int ResetTcp(HashSet<int> pids)
    {
        if (pids.Count == 0) return 0;
        var size = 0;
        var buf = IntPtr.Zero;
        try
        {
            uint ret;
            do
            {
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
                Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal(size);
                ret = GetExtendedTcpTable(buf, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
            } while (ret == ErrorInsufficientBuffer);
            if (ret != 0) return 0;

            var count = Marshal.ReadInt32(buf);
            var rowSize = Marshal.SizeOf<TcpRowOwnerPid>();
            var killed = 0;
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<TcpRowOwnerPid>(buf + 4 + i * rowSize);
                // Адрес в сетевом порядке байт: первый октет в младшем байте.
                if (row.State != StateEstablished || !pids.Contains((int)row.OwningPid) || (row.RemoteAddr & 0xFF) == 127)
                    continue;
                var del = new TcpRow
                {
                    State = StateDeleteTcb,
                    LocalAddr = row.LocalAddr,
                    LocalPort = row.LocalPort,
                    RemoteAddr = row.RemoteAddr,
                    RemotePort = row.RemotePort,
                };
                if (SetTcpEntry(ref del) == 0) killed++;
            }
            return killed;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }
}
