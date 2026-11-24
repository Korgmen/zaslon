// Окно настроек и окно выбора приложений. Любое изменение сразу пишется в config.json и применяется.

using System.Diagnostics;

namespace Zaslon;

sealed class SettingsForm : Form
{
    const int TextWidth = 500;

    readonly Guard g;
    readonly List<Action> refills = [];
    bool loading;

    readonly CheckBox autostart = new() { Text = "Запускать при входе в систему", AutoSize = true };
    readonly Label autostartError = new() { AutoSize = true, ForeColor = Color.Firebrick, MaximumSize = new Size(TextWidth, 0), Visible = false };
    readonly NumericUpDown interval = new() { Minimum = 2, Maximum = 60, Width = 70 };
    readonly NumericUpDown agree = new() { Minimum = 1, Maximum = Net.V4Urls.Length, Width = 70 };
    readonly CheckBox ipv6 = new() { Text = "Следить за IPv6", AutoSize = true };

    public SettingsForm(Guard g)
    {
        this.g = g;
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "Zaslon: настройки";
        Icon = new Icon(typeof(SettingsForm).Assembly.GetManifestResourceStream("AppIcon.ico")!);
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(TextWidth + 70, 640);
        MinimumSize = new Size(TextWidth + 90, 300);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            ColumnCount = 1,
            Padding = new Padding(12, 8, 12 + SystemInformation.VerticalScrollBarWidth, 12),
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Controls.Add(root);

        var pick = new Button { Text = "Выбрать приложения…", AutoSize = true };
        pick.Click += (_, _) =>
        {
            using var p = new AppPicker(this.g, Changed);
            p.ShowDialog(this);
            Reload();
        };
        root.Controls.Add(ListSection("Защищённые приложения", () => this.g.Cfg.Apps,
            @"Своё правило: часть пути к exe, например \telegram.exe",
            s => s.Trim().Length > 0 ? s.Trim() : null, pick,
            "Правило — часть полного пути к exe без учёта регистра. Сеть блокируется у каждого подходящего exe целиком."));

        root.Controls.Add(ListSection("Разрешённые IP и подсети", () => this.g.Cfg.AllowIPs,
            "Например 185.12.40.0/24", s => Ip.IsValidRule(s.Trim()) ? s.Trim() : null));

        root.Controls.Add(ListSection("Разрешённые страны", () => this.g.Cfg.AllowCountries,
            "Код страны, например NL",
            s => s.Trim() is { Length: 2 } cc && cc.All(char.IsAsciiLetter) ? cc.ToUpperInvariant() : null));

        autostart.CheckedChanged += (_, _) =>
        {
            if (loading) return;
            var err = LoginItem.Set(autostart.Checked);
            autostartError.Text = err == null ? "" : $"Не удалось изменить автозапуск: {err}";
            autostartError.Visible = err != null;
            Reload();
        };
        root.Controls.Add(Section("Запуск",
            autostart,
            Hint("Zaslon стартует сам при входе в Windows, с правами администратора и без запроса UAC. В планировщик записывается путь, откуда Zaslon запущен сейчас."),
            autostartError));

        interval.ValueChanged += (_, _) => Set(() => this.g.Cfg.CheckInterval = (double)interval.Value);
        agree.ValueChanged += (_, _) => Set(() => this.g.Cfg.MinAgree = (int)agree.Value);
        ipv6.CheckedChanged += (_, _) => Set(() => this.g.Cfg.CheckIPv6 = ipv6.Checked);
        root.Controls.Add(Section("Поведение",
            Row("Интервал проверки, с:", interval),
            Hint("Как часто проверять IP, когда всё в порядке. При переподключении VPN или смене сети проверка идёт сразу, не дожидаясь интервала. Меньше значение — быстрее реакция, но больше запросов к сервисам проверки."),
            Row($"Согласие сервисов, из {Net.V4Urls.Length}:", agree),
            Hint($"IP узнаётся у {Net.V4Urls.Length} независимых сервисов. Адрес считается настоящим, когда столько из них назвали один и тот же. Если из-за медленной сети ответили не все, но все назвали один адрес, он тоже принимается. Блокировка — когда сервисы называют разные адреса или не отвечает ни один две проверки подряд."),
            ipv6,
            Hint("Многие VPN защищают только IPv4, а IPv6 идёт в обход и выдаёт ваш настоящий адрес. Если включено, IPv6-адрес не из разрешённых считается утечкой и сеть приложений блокируется. Если IPv6 у вас нет, настройка ни на что не влияет.")));

        var showConfig = new Button { Text = "Показать файл настроек", AutoSize = true };
        showConfig.Click += (_, _) => Process.Start("explorer.exe", $"/select,\"{Paths.Config}\"");
        root.Controls.Add(Section("О приложении",
            new Label { Text = $"Zaslon {Application.ProductVersion}", AutoSize = true, Font = new Font(Font, FontStyle.Bold) },
            new Label
            {
                Text = "Kill switch для отдельных приложений. Если VPN отключился, IP сменился или пропал интернет, Zaslon блокирует выбранным приложениям сеть правилом брандмауэра Windows. Приложения продолжают работать, но наружу ничего не уходит. Вернулся разрешённый IP — сеть возвращается.",
                AutoSize = true,
                MaximumSize = new Size(TextWidth, 0),
            },
            Hint("Между сменой сети и блокировкой проходят доли секунды. Если важно, чтобы наружу не ушёл ни один пакет, включите ещё и kill switch в самом VPN-клиенте."),
            Hint("Для проверки адреса Zaslon обращается к api.ipify.org, icanhazip.com, ident.me, checkip.amazonaws.com и ipinfo.io, страну узнаёт у ipinfo.io и api.country.is, DNS-сервер — запросом whoami.akamai.net. Больше никуда данные не отправляются."),
            showConfig));

        ResumeLayout(false);
        PerformLayout();
        Reload();
    }

    /// Перечитывает значения из конфига, например после правки файла руками.
    public void Reload()
    {
        loading = true;
        foreach (var r in refills) r();
        interval.Value = Math.Clamp((decimal)g.Cfg.CheckInterval, interval.Minimum, interval.Maximum);
        agree.Value = Math.Clamp(g.Cfg.MinAgree, (int)agree.Minimum, (int)agree.Maximum);
        ipv6.Checked = g.Cfg.CheckIPv6;
        autostart.Checked = LoginItem.Enabled;
        loading = false;
    }

    void Changed()
    {
        g.SaveConfig();
        g.ConfigChanged();
    }

    void Set(Action change)
    {
        if (loading) return;
        change();
        Changed();
    }

    // Разметка

    static Label Hint(string text) => new()
    {
        Text = text,
        AutoSize = true,
        MaximumSize = new Size(TextWidth, 0),
        ForeColor = SystemColors.GrayText,
        Margin = new Padding(3, 0, 3, 8),
    };

    static FlowLayoutPanel Row(string label, Control c)
    {
        var p = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        p.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 6, 3, 3) });
        p.Controls.Add(c);
        return p;
    }

    static GroupBox Section(string title, params Control[] items)
    {
        var box = new GroupBox
        {
            Text = title,
            Dock = DockStyle.Fill,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(8),
            Margin = new Padding(0, 0, 0, 10),
        };
        var flow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
        };
        flow.Controls.AddRange(items);
        box.Controls.Add(flow);
        return box;
    }

    /// Список строк из конфига: удаление выбранной, добавление из поля ввода.
    /// normalize возвращает значение для добавления или null, если ввод не годится.
    GroupBox ListSection(string title, Func<List<string>> list, string placeholder, Func<string, string?> normalize,
                         Control? extra = null, string? hint = null)
    {
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2 };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var items = new ListBox { Dock = DockStyle.Fill, Height = 96, IntegralHeight = false };
        var remove = new Button { Text = "Убрать", AutoSize = true, Enabled = false, Anchor = AnchorStyles.Top | AnchorStyles.Left };
        var input = new TextBox { Dock = DockStyle.Fill, PlaceholderText = placeholder };
        var add = new Button { Text = "Добавить", AutoSize = true, Enabled = false };
        t.Controls.Add(items, 0, 0);
        t.Controls.Add(remove, 1, 0);
        t.Controls.Add(input, 0, 1);
        t.Controls.Add(add, 1, 1);
        if (extra != null) t.Controls.Add(extra, 0, 2);
        if (hint != null)
        {
            var h = Hint(hint);
            t.Controls.Add(h, 0, 3);
            t.SetColumnSpan(h, 2);
        }

        string? Valid() => normalize(input.Text) is { } v && !list().Contains(v, StringComparer.OrdinalIgnoreCase) ? v : null;

        items.SelectedIndexChanged += (_, _) => remove.Enabled = items.SelectedIndex >= 0;
        input.TextChanged += (_, _) => add.Enabled = Valid() != null;
        add.Click += (_, _) =>
        {
            if (Valid() is not { } v) return;
            list().Add(v);
            input.Clear();
            Changed();
            Reload();
        };
        input.KeyDown += (_, e) =>
        {
            if (e.KeyCode != Keys.Enter) return;
            e.SuppressKeyPress = true;
            add.PerformClick();
        };
        remove.Click += (_, _) =>
        {
            if (items.SelectedItem is not string v) return;
            list().Remove(v);
            Changed();
            Reload();
        };
        refills.Add(() =>
        {
            items.Items.Clear();
            items.Items.AddRange([.. list()]);
            remove.Enabled = false;
        });
        return Section(title, t);
    }
}

/// Приложение из меню «Пуск» или запущенное с окном; правило защиты: "\имя.exe".
sealed record AppEntry(string Rule, string Name, string Path);

sealed class AppPicker : Form
{
    readonly Guard g;
    readonly Action changed;
    readonly List<AppEntry> catalog = InstalledApps();
    readonly ListView list = new()
    {
        Dock = DockStyle.Fill,
        View = View.Details,
        CheckBoxes = true,
        FullRowSelect = true,
        HeaderStyle = ColumnHeaderStyle.Nonclickable,
    };
    readonly TextBox search = new() { Dock = DockStyle.Top, PlaceholderText = "Поиск" };
    bool filling;

    public AppPicker(Guard g, Action changed)
    {
        this.g = g;
        this.changed = changed;
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "Выбор приложений";
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        MinimizeBox = false;
        ClientSize = new Size(480, 540);

        list.Columns.Add("Приложение", 220);
        list.Columns.Add("Правило", 220);
        list.SmallImageList = new ImageList { ColorDepth = ColorDepth.Depth32Bit, ImageSize = new Size(16, 16) };
        foreach (var a in catalog)
        {
            try
            {
                // ImageList хранит ссылку на добавленный объект и читает его при создании окна:
                // отдаём независимую копию, а сам значок освобождаем.
                using var icon = Icon.ExtractAssociatedIcon(a.Path);
                if (icon != null) list.SmallImageList.Images.Add(a.Rule, icon.ToBitmap());
            }
            catch (Exception e) when (e is IOException or ArgumentException) { }
        }
        list.ItemChecked += (_, e) =>
        {
            if (filling || e.Item.Tag is not AppEntry a) return;
            var apps = this.g.Cfg.Apps;
            if (e.Item.Checked)
            {
                if (!apps.Contains(a.Rule, StringComparer.OrdinalIgnoreCase)) apps.Add(a.Rule);
            }
            else
            {
                apps.RemoveAll(r => r.Equals(a.Rule, StringComparison.OrdinalIgnoreCase));
            }
            this.changed();
        };
        search.TextChanged += (_, _) => Fill();

        var bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(6) };
        var done = new Button { Text = "Готово", AutoSize = true, DialogResult = DialogResult.OK };
        AcceptButton = done;
        bottom.Controls.Add(done);
        bottom.Controls.Add(new Label
        {
            Text = "У отмеченных блокируется сеть всех их процессов",
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Margin = new Padding(3, 8, 12, 3),
        });

        Controls.Add(list);
        Controls.Add(search);
        Controls.Add(bottom);
        ResumeLayout(false);
        PerformLayout();
        Fill();
    }

    void Fill()
    {
        filling = true;
        list.BeginUpdate();
        list.Items.Clear();
        var q = search.Text.Trim();
        foreach (var a in catalog.Where(a => q.Length == 0 || a.Name.Contains(q, StringComparison.CurrentCultureIgnoreCase)))
        {
            var item = new ListViewItem([a.Name, a.Rule])
            {
                Tag = a,
                ImageKey = a.Rule,
                Checked = g.Cfg.Apps.Contains(a.Rule, StringComparer.OrdinalIgnoreCase),
            };
            list.Items.Add(item);
        }
        list.EndUpdate();
        filling = false;
    }

    /// Ярлыки .exe из меню «Пуск» (общего и пользователя) и запущенные программы с окном.
    static List<AppEntry> InstalledApps()
    {
        var found = new Dictionary<string, AppEntry>(StringComparer.OrdinalIgnoreCase);
        void Add(string exe, string name)
        {
            if (!exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(exe)) return;
            var file = Path.GetFileName(exe);
            if (file.StartsWith("unins", StringComparison.OrdinalIgnoreCase)) return;
            found.TryAdd(@"\" + file, new AppEntry(@"\" + file, name, exe));
        }

        var shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell", true)!) as dynamic;
        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
        foreach (var dir in new[] { Environment.SpecialFolder.CommonPrograms, Environment.SpecialFolder.Programs })
        {
            var root = Environment.GetFolderPath(dir);
            if (!Directory.Exists(root)) continue;
            foreach (var lnk in Directory.EnumerateFiles(root, "*.lnk", opts))
            {
                try
                {
                    string target = shell!.CreateShortcut(lnk).TargetPath;
                    Add(target, Path.GetFileNameWithoutExtension(lnk));
                }
                catch (Exception) { }
            }
        }
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.MainWindowHandle == IntPtr.Zero || Procs.ImagePath(p.Id) is not { } exe) continue;
                var desc = FileVersionInfo.GetVersionInfo(exe).FileDescription;
                Add(exe, string.IsNullOrWhiteSpace(desc) ? p.ProcessName : desc);
            }
        }
        return [.. found.Values.OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)];
    }
}
