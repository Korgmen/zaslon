// Автозапуск: задача планировщика «при входе пользователя» с наивысшими правами, поэтому без запроса UAC.

using System.Diagnostics;
using System.Globalization;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace Zaslon;

static class LoginItem
{
    const string TaskName = "Zaslon";

    public static bool Enabled => Schtasks("/Query", "/TN", TaskName).Code == 0;

    /// Регистрируется путь, откуда запущен exe. Возвращает текст ошибки или null.
    public static string? Set(bool on)
    {
        string? error;
        if (on)
        {
            var xml = Path.Combine(Path.GetTempPath(), "zaslon-task.xml");
            File.WriteAllText(xml, TaskXml(), Encoding.Unicode);
            try
            {
                error = Error(Schtasks("/Create", "/TN", TaskName, "/XML", xml, "/F"));
            }
            finally
            {
                File.Delete(xml);
            }
        }
        else
        {
            error = Error(Schtasks("/Delete", "/TN", TaskName, "/F"));
        }
        Log.Write(error == null ? $"автозапуск {(on ? "включён" : "выключен")}" : $"автозапуск: ошибка {error}");
        return error;
    }

    static string? Error((int Code, string Output) r) => r.Code == 0 ? null : r.Output;

    /// Без лимита времени и без условий питания: по умолчанию планировщик останавливает задачу через 72 часа
    /// и не запускает её от батареи.
    static string TaskXml()
    {
        var user = SecurityElement.Escape(WindowsIdentity.GetCurrent().Name);
        var exe = SecurityElement.Escape(Environment.ProcessPath ?? "");
        return $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>Zaslon: kill switch для приложений</Description></RegistrationInfo>
              <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>{user}</UserId>
                  <LogonType>InteractiveToken</LogonType>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>5</Priority>
              </Settings>
              <Actions Context="Author"><Exec><Command>{exe}</Command></Exec></Actions>
            </Task>
            """;
    }

    static (int Code, string Output) Schtasks(params string[] args)
    {
        // schtasks пишет в кодировке OEM (866 для русской Windows).
        var oem = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
        var psi = new ProcessStartInfo("schtasks.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = oem,
            StandardErrorEncoding = oem,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            var err = p.StandardError.ReadToEndAsync();
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            return (p.ExitCode, (output + err.Result).Trim());
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return (-1, e.Message);
        }
    }
}
