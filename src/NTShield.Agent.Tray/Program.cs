namespace NTShield.Agent.Tray;

internal static class Program
{
    private const string MutexName = "Global\\NTShield.Agent.Tray.SingleInstance";

    [STAThread]
    private static void Main(string[] args)
    {
        using var mutex = new Mutex(true, MutexName, out var createdNew);
        if (!createdNew)
        {
            // Already running in this session — do not open a second icon.
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        var installDir = ResolveInstallDir(args);
        Application.Run(new TrayAppContext(installDir));
    }

    private static string ResolveInstallDir(string[] args)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], "--install-dir", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(args[i], "-d", StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1].Trim('"');
            }
        }

        // Running from install folder (next to Agent.exe)
        var baseDir = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (File.Exists(Path.Combine(baseDir, "NTShield.Agent.exe")) ||
            File.Exists(Path.Combine(baseDir, "appsettings.json")))
        {
            return baseDir;
        }

        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NT Shield Agent"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NT Shield", "Agent"),
            baseDir
        };

        foreach (var c in candidates)
        {
            if (Directory.Exists(c))
            {
                return c;
            }
        }

        return baseDir;
    }
}
