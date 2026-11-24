// Zaslon для Windows: kill switch для приложений.
// Публичный IP не из белого списка -> защищённые exe получают блокирующие правила брандмауэра,
// разрешённый IP вернулся -> правила снимаются.

using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Zaslon;

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        if (args.Contains("--check")) return Check().GetAwaiter().GetResult();

        // Global: правила брандмауэра общие для всех сеансов Windows.
        using var single = new Mutex(true, @"Global\Zaslon", out var first);
        ApplicationConfiguration.Initialize();
        if (!first)
        {
            MessageBox.Show("Zaslon уже запущен.", "Zaslon", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 1;
        }
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
        {
            MessageBox.Show("Zaslon нужны права администратора: без них он не может менять правила брандмауэра.",
                            "Zaslon", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());
        Application.Run(new TrayApp());
        return 0;
    }

    [DllImport("kernel32.dll")]
    static extern bool AttachConsole(int pid);

    [DllImport("kernel32.dll")]
    static extern bool AllocConsole();

    /// Только проверка: ничего не блокирует и не пишет конфиг. Код выхода 0, если IP разрешён.
    static async Task<int> Check()
    {
        // Приложение оконное, своей консоли у него нет. Запуск из неповышенного терминала
        // проходит через UAC, к консоли терминала тогда не подключиться: открывается своя.
        var own = !AttachConsole(-1) && AllocConsole();
        var g = new Guard(save: false);
        var r = await g.RunCheck();
        var dns = await Net.DnsResolverIP();
        string Line(string? ip, string? cc) =>
            ip == null ? "нет" : $"{ip} ({cc ?? "?"}) " + (g.IsAllowed(ip, cc) ? "разрешён" : "НЕ разрешён");

        Console.WriteLine();
        Console.WriteLine($"Конфиг: {Paths.Config}" + (g.CfgError != null ? $" ({g.CfgError})" : ""));
        Console.WriteLine($"IPv4:  {Line(r.V4, r.V4Country)}" + (r.V4Others.Count == 0 ? "" : $"; другие ответы: {string.Join(", ", r.V4Others)}"));
        Console.WriteLine($"IPv6:  {Line(r.V6, r.V6Country)}");
        Console.WriteLine($"DNS:   {dns ?? "нет"}");
        Console.WriteLine("Итог:  " + (r.Good ? "OK" : $"БЛОКИРОВКА ({r.Reason})"));
        Console.WriteLine("Процессы под защитой:");
        foreach (var (pid, path) in g.Matching()) Console.WriteLine($"  {pid}  {path}");
        Console.WriteLine("Брандмауэр: " + (Firewall.Warning() ?? "включён"));
        if (own)
        {
            Console.WriteLine("Enter — закрыть окно");
            Console.ReadLine();
        }
        return r.Good ? 0 : 1;
    }
}
