// Значок в области уведомлений и его меню.

using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Net.NetworkInformation;
using Microsoft.Win32;

namespace Zaslon;

sealed class TrayApp : ApplicationContext
{
    readonly Guard g = new(save: true);
    readonly NotifyIcon tray = new();
    readonly ContextMenuStrip menu = new();
    readonly System.Windows.Forms.Timer timer = new() { Interval = 1000 };
    readonly SynchronizationContext ui;
    readonly Dictionary<Color, Icon> icons = [];
    SettingsForm? settings;

    static readonly Color Gray = Color.FromArgb(0x9c, 0xa3, 0xaf), Green = Color.FromArgb(0x22, 0xc5, 0x5e),
                          Red = Color.FromArgb(0xef, 0x44, 0x44);

    public TrayApp()
    {
        ui = SynchronizationContext.Current!;
        g.OnChange = Render;
        g.OnConfigReloaded = () => settings?.Reload();
        Log.Write($"=== Zaslon {Application.ProductVersion} запущен; защищаются: [{string.Join(", ", g.Cfg.Apps)}]");

        try
        {
            var left = Firewall.LoadExisting();
            if (left > 0) Log.Write($"правила прошлого запуска: {left}, действуют до первой проверки");
            var released = g.ReleaseUnprotected();
            if (released > 0) Log.Write($"сняты правила с программ не под защитой: {released}");
        }
        catch (Exception e)
        {
            Log.Write($"не удалось прочитать правила брандмауэра: {e.Message}");
        }
        g.FirewallWarning = Firewall.Warning();
        if (g.FirewallWarning != null) Log.Write($"ВНИМАНИЕ: {g.FirewallWarning}");

        menu.Opening += (_, e) =>
        {
            BuildMenu();
            e.Cancel = false;
        };
        tray.ContextMenuStrip = menu;
        tray.DoubleClick += (_, _) => OpenSettings();
        tray.Visible = true;
        Render();

        g.PathChanged(NetSignature());
        NetworkChange.NetworkAddressChanged += (_, _) => ui.Post(_ => g.PathChanged(NetSignature()), null);
        NetworkChange.NetworkAvailabilityChanged += (_, _) => ui.Post(_ => g.PathChanged(NetSignature()), null);
        SystemEvents.PowerModeChanged += (_, e) => ui.Post(_ =>
        {
            if (e.Mode == PowerModes.Suspend) Log.Write("Windows засыпает");
            if (e.Mode != PowerModes.Resume) return;
            Log.Write("Windows проснулась");
            _ = g.Check();
        }, null);

        timer.Tick += (_, _) => g.Tick();
        timer.Start();
        _ = g.Check();
    }

    /// Существенное в состоянии сети: есть ли сеть и какие адаптеры (Ethernet, Wi-Fi, адаптер VPN) включены.
    static string NetSignature()
    {
        var ifs = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(n => n.Name)
            .Order(StringComparer.Ordinal);
        return $"{(NetworkInterface.GetIsNetworkAvailable() ? "есть сеть" : "нет сети")} [{string.Join(", ", ifs)}]";
    }

    // Значок

    Icon StatusIcon(Color c)
    {
        if (icons.TryGetValue(c, out var cached)) return cached;
        var size = SystemInformation.SmallIconSize;
        using var stream = typeof(TrayApp).Assembly.GetManifestResourceStream("AppIcon.ico")!;
        using var app = new Icon(stream, size);
        using var bmp = new Bitmap(size.Width, size.Height);
        using (var gr = Graphics.FromImage(bmp))
        {
            gr.SmoothingMode = SmoothingMode.AntiAlias;
            gr.DrawIcon(app, new Rectangle(Point.Empty, size));
            var d = size.Width * 0.55f;
            var dot = new RectangleF(size.Width - d, size.Height - d, d, d);
            using var rim = new SolidBrush(Color.FromArgb(0x1f, 0x2a, 0x44));
            gr.FillEllipse(rim, dot);
            dot.Inflate(-size.Width * 0.08f, -size.Width * 0.08f);
            using var fill = new SolidBrush(c);
            gr.FillEllipse(fill, dot);
        }
        // Значков всего три, живут до выхода: DestroyIcon для них не нужен.
        return icons[c] = Icon.FromHandle(bmp.GetHicon());
    }

    void Render()
    {
        var r = g.Last;
        var (color, detail) = g.State switch
        {
            State.Ok => (Green, $"{r.V4Country} {r.V4}".Trim()),
            State.Blocked => (Red, r.Reason),
            _ => (Gray, ""),
        };
        var icon = StatusIcon(color);
        if (tray.Icon != icon) tray.Icon = icon;
        var text = $"Zaslon: {g.StatusText}" + (detail.Length > 0 ? $"\n{detail}" : "");
        if (text.Length > 127) text = text[..127];
        if (tray.Text != text) tray.Text = text;
    }

    // Меню

    void BuildMenu()
    {
        foreach (var old in menu.Items.Cast<ToolStripItem>().ToList()) old.Dispose();
        menu.Items.Clear();
        var r = g.Last;

        void Info(string s) => menu.Items.Add(new ToolStripMenuItem(s) { Enabled = false });
        ToolStripMenuItem Action(string title, Action act)
        {
            var i = new ToolStripMenuItem(title);
            i.Click += (_, _) => act();
            menu.Items.Add(i);
            return i;
        }
        string Show(string? ip, string? cc, bool mark)
        {
            if (ip == null) return "нет";
            var tag = mark ? (g.IsAllowed(ip, cc) ? "  разрешён" : "  НЕ разрешён") : "";
            return $"{ip} ({cc ?? "?"}){tag}";
        }

        Info($"Статус: {g.StatusText}");
        if (!r.Good && r.Reason.Length > 0) Info($"Причина: {r.Reason}");
        if (g.FirewallWarning != null) Info($"Внимание: {g.FirewallWarning}");
        if (g.CfgError != null) Info($"Конфиг: {g.CfgError}");
        Info($"IPv4: {Show(r.V4, r.V4Country, true)}");
        if (r.V4Others.Count > 0) Info($"   другие ответы: {string.Join(", ", r.V4Others)}");
        if (g.Cfg.CheckIPv6) Info($"IPv6: {Show(r.V6, r.V6Country, true)}");
        Info($"DNS-резолвер: {Show(g.DnsIP, g.DnsCountry, false)}");
        var pids = g.Matching().Count;
        Info($"Процессов под защитой: {pids}" + (Firewall.Paths.Count == 0 ? "" : $", заблокировано программ: {Firewall.Paths.Count}"));

        menu.Items.Add(new ToolStripSeparator());
        Action("Проверить сейчас", () => _ = g.Check());
        foreach (var (ip, cc) in new[] { (r.V4, r.V4Country), (r.V6, r.V6Country) })
        {
            if (ip == null || g.IsAllowed(ip, cc)) continue;
            Action($"Разрешить IP {ip}", () => Allow(g.Cfg.AllowIPs, ip));
            if (cc != null) Action($"Разрешить страну {cc}", () => Allow(g.Cfg.AllowCountries, cc));
        }
        Action(g.State == State.Paused ? "Возобновить защиту" : "Приостановить защиту",
               () => g.SetPaused(g.State != State.Paused));
        var login = Action("Запускать при входе в систему", () =>
        {
            var err = LoginItem.Set(!LoginItem.Enabled);
            settings?.Reload();
            if (err != null) MessageBox.Show($"Не удалось изменить автозапуск: {err}", "Zaslon", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        });
        login.Checked = LoginItem.Enabled;
        Action("Настройки…", OpenSettings);
        Action("Открыть лог", OpenLog);
        menu.Items.Add(new ToolStripSeparator());
        Action("Выход", Quit);
    }

    void Allow(List<string> list, string value)
    {
        if (!list.Contains(value, StringComparer.OrdinalIgnoreCase)) list.Add(value);
        g.SaveConfig();
        settings?.Reload();
        g.ConfigChanged();
    }

    void OpenSettings()
    {
        if (settings == null)
        {
            settings = new SettingsForm(g);
            settings.FormClosed += (_, _) => settings = null;
            settings.Show();
        }
        settings.Reload();
        if (settings.WindowState == FormWindowState.Minimized) settings.WindowState = FormWindowState.Normal;
        settings.Activate();
    }

    static void OpenLog()
    {
        if (!File.Exists(Paths.Log)) Log.Write("лог создан");
        try
        {
            Process.Start(new ProcessStartInfo(Paths.Log) { UseShellExecute = true });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Process.Start("notepad.exe", Paths.Log);
        }
    }

    void Quit()
    {
        timer.Stop();
        var n = Firewall.UnblockAll();
        Log.Write($"=== Zaslon завершён, разблокировано программ: {n}");
        tray.Visible = false;
        settings?.Close();
        ExitThread();
    }
}
