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
        foreach (var path in rules.Keys) Wfp.Block(path);
        return rules.Count;
    }

    /// Запрещает exe входящие и исходящие соединения во всех профилях сети. Loopback брандмауэр не фильтрует:
    /// его закрывает фильтр WFP.
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
        Wfp.Block(path);
    }

    public static void Unblock(string path)
    {
        if (!rules.Remove(path, out var names)) return;
        Wfp.Unblock(path);
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

    /// Рвёт установленные IPv4-соединения процессов, включая loopback (локальный прокси): новые правила
    /// гарантированно действуют на новые соединения. Для IPv6 у Windows такого API нет.
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
                if (row.State != StateEstablished || !pids.Contains((int)row.OwningPid)) continue;
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

/// Фильтры WFP: запрет исходящих соединений exe, включая loopback, который правила брандмауэра не видят.
/// Динамическая сессия: фильтры исчезают при выходе или падении Zaslon, постоянные правила брандмауэра остаются.
static class Wfp
{
    static readonly Guid SubLayer = new("7f1d3c2a-5b8e-4c61-9a0d-2e4f6b8c1a37");
    static readonly Guid LayerConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    static readonly Guid LayerConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid ConditionAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    const uint SessionDynamic = 1, AuthnWinNT = 10, FilterClearActionRight = 8, ActionBlock = 0x1001, BlobType = 12;

    static IntPtr engine;
    static readonly Dictionary<string, ulong[]> filters = new(StringComparer.OrdinalIgnoreCase);

    [StructLayout(LayoutKind.Sequential)]
    struct DisplayData { public IntPtr Name, Description; }

    [StructLayout(LayoutKind.Sequential)]
    struct Blob { public uint Size; public IntPtr Data; }

    [StructLayout(LayoutKind.Sequential)]
    struct Value { public uint Type; public IntPtr Data; }

    [StructLayout(LayoutKind.Sequential)]
    struct Session
    {
        public Guid Key; public DisplayData Display; public uint Flags, TxnWaitTimeout, ProcessId;
        public IntPtr Sid, Username; public int KernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SubLayerRec { public Guid Key; public DisplayData Display; public uint Flags; public IntPtr ProviderKey; public Blob ProviderData; public ushort Weight; }

    [StructLayout(LayoutKind.Sequential)]
    struct Condition { public Guid Field; public uint Match; public Value Value; }

    [StructLayout(LayoutKind.Sequential)]
    struct Filter
    {
        public Guid Key; public DisplayData Display; public uint Flags; public IntPtr ProviderKey; public Blob ProviderData;
        public Guid Layer, SubLayer; public Value Weight; public uint NumConditions; public IntPtr Conditions;
        public uint ActionType; public Guid ActionKey; public ulong Context1, Context2; public IntPtr Reserved;
        public ulong Id; public Value EffectiveWeight;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    static extern uint FwpmEngineOpen0(string? server, uint authn, IntPtr identity, ref Session session, out IntPtr engine);

    [DllImport("fwpuclnt.dll")]
    static extern uint FwpmEngineClose0(IntPtr engine);

    [DllImport("fwpuclnt.dll")]
    static extern uint FwpmSubLayerAdd0(IntPtr engine, ref SubLayerRec subLayer, IntPtr sd);

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll")]
    static extern void FwpmFreeMemory0(ref IntPtr p);

    [DllImport("fwpuclnt.dll")]
    static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr sd, out ulong id);

    [DllImport("fwpuclnt.dll")]
    static extern uint FwpmFilterDeleteById0(IntPtr engine, ulong id);

    static void Check(uint err, string what)
    {
        if (err != 0) throw new InvalidOperationException($"{what}: 0x{err:X8}");
    }

    static void Open()
    {
        if (engine != IntPtr.Zero) return;
        var name = Marshal.StringToHGlobalUni("Zaslon");
        try
        {
            var session = new Session { Display = new DisplayData { Name = name }, Flags = SessionDynamic };
            Check(FwpmEngineOpen0(null, AuthnWinNT, IntPtr.Zero, ref session, out var h), "FwpmEngineOpen0");
            // Самый тяжёлый подслой: его запрет вычисляется первым и, со сброшенным правом, не отменяется
            // разрешением loopback из подслоя брандмауэра Windows.
            var sub = new SubLayerRec { Key = SubLayer, Display = new DisplayData { Name = name }, Weight = 0xFFFF };
            var err = FwpmSubLayerAdd0(h, ref sub, IntPtr.Zero);
            if (err != 0) FwpmEngineClose0(h);
            Check(err, "FwpmSubLayerAdd0");
            engine = h;
        }
        finally
        {
            Marshal.FreeHGlobal(name);
        }
    }

    /// Ошибку только пишет в лог: правила брандмауэра к этому моменту уже действуют.
    public static void Block(string path)
    {
        if (filters.ContainsKey(path)) return;
        var appId = IntPtr.Zero;
        var cond = Marshal.AllocHGlobal(Marshal.SizeOf<Condition>());
        var name = Marshal.StringToHGlobalUni($"Zaslon: {path}");
        var ids = new List<ulong>();
        try
        {
            Open();
            Check(FwpmGetAppIdFromFileName0(path, out appId), "FwpmGetAppIdFromFileName0");
            Marshal.StructureToPtr(new Condition { Field = ConditionAppId, Value = new Value { Type = BlobType, Data = appId } }, cond, false);
            foreach (var layer in new[] { LayerConnectV4, LayerConnectV6 })
            {
                var f = new Filter
                {
                    Display = new DisplayData { Name = name },
                    Flags = FilterClearActionRight,
                    Layer = layer,
                    SubLayer = SubLayer,
                    NumConditions = 1,
                    Conditions = cond,
                    ActionType = ActionBlock,
                };
                Check(FwpmFilterAdd0(engine, ref f, IntPtr.Zero, out var id), "FwpmFilterAdd0");
                ids.Add(id);
            }
            filters[path] = [.. ids];
        }
        catch (Exception e)
        {
            foreach (var id in ids) FwpmFilterDeleteById0(engine, id);
            Log.Write($"WFP: не удалось заблокировать {path}: {e.Message}");
        }
        finally
        {
            if (appId != IntPtr.Zero) FwpmFreeMemory0(ref appId);
            Marshal.FreeHGlobal(cond);
            Marshal.FreeHGlobal(name);
        }
    }

    public static void Unblock(string path)
    {
        if (!filters.Remove(path, out var ids)) return;
        foreach (var id in ids)
        {
            var err = FwpmFilterDeleteById0(engine, id);
            if (err != 0) Log.Write($"WFP: не удалось снять фильтр для {path}: 0x{err:X8}");
        }
    }
}
