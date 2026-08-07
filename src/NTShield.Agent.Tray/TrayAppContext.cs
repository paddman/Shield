using System.Diagnostics;
using System.Drawing.Imaging;
using System.ServiceProcess;
using System.Text.Json;

namespace NTShield.Agent.Tray;

/// <summary>
/// System tray companion + mini dashboard for the Agent Windows Service.
/// </summary>
internal sealed class TrayAppContext : ApplicationContext
{
    private const string ServiceName = "NTShieldAgent";
    private const string LogDir = @"C:\ProgramData\NTShield\Agent\logs";

    private readonly string _installDir;
    private readonly NotifyIcon _tray;
    private readonly ContextMenuStrip _menu;
    private readonly ToolStripMenuItem _statusItem;
    private readonly ToolStripMenuItem _hostItem;
    private readonly ToolStripMenuItem _urlItem;
    private readonly System.Windows.Forms.Timer _timer;
    private Icon? _icon;
    private MiniDashboardForm? _dash;
    private AiConsoleForm? _aiConsole;

    public TrayAppContext(string installDir)
    {
        _installDir = installDir;
        _icon = LoadIcon();

        _statusItem = new ToolStripMenuItem("Status: ...") { Enabled = false };
        _hostItem = new ToolStripMenuItem("Host: ...") { Enabled = false };
        _urlItem = new ToolStripMenuItem("Central: ...") { Enabled = true };
        _urlItem.Click += (_, _) => ShowEditCentral();

        _menu = new ContextMenuStrip();
        var trayVer = GetTrayVersion();
        _menu.Items.Add(new ToolStripLabel($"NT Shield Agent  v{trayVer}")
        {
            Font = new Font(SystemFonts.MenuFont!, FontStyle.Bold)
        });
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add(_statusItem);
        _menu.Items.Add(_hostItem);
        _menu.Items.Add(_urlItem);
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add("Edit Central IP / Port…", null, (_, _) => ShowEditCentral());
        _menu.Items.Add("Test Central connection…", null, async (_, _) => await TestCentralAsync());
        _menu.Items.Add("Open mini dashboard", null, (_, _) => ShowMiniDashboard());
        _menu.Items.Add("Close mini dashboard", null, (_, _) => HideMiniDashboard());
        _menu.Items.Add("Open AI realtime console", null, (_, _) => ShowAiConsole());
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add("Service Control (Start/Stop)…", null, (_, _) => ShowServiceControl());
        _menu.Items.Add("Install / Register Agent service…", null, (_, _) => InstallAgentService());
        _menu.Items.Add("Start Agent service", null, (_, _) => ControlAgentService("start"));
        _menu.Items.Add("Stop Agent service", null, (_, _) => ControlAgentService("stop"));
        _menu.Items.Add("Restart Agent service", null, (_, _) => ControlAgentService("restart"));
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add("Refresh status", null, (_, _) => RefreshStatus());
        _menu.Items.Add("Open logs folder", null, (_, _) => OpenFolder(LogDir));
        _menu.Items.Add("Open install folder", null, (_, _) => OpenFolder(_installDir));
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add("Exit tray icon (agent still runs)", null, (_, _) => ExitTray());

        var trayIcon = _icon ?? CreateFallbackIcon();
        _icon = trayIcon;

        _tray = new NotifyIcon
        {
            Text = "NT Shield Agent",
            Icon = trayIcon,
            ContextMenuStrip = _menu,
            Visible = false
        };
        _tray.DoubleClick += (_, _) => ShowMiniDashboard();
        _tray.MouseClick += Tray_MouseClick;
        _tray.Visible = true;

        _timer = new System.Windows.Forms.Timer { Interval = 10_000 };
        _timer.Tick += (_, _) => RefreshStatus();
        _timer.Start();

        var kick = new System.Windows.Forms.Timer { Interval = 500 };
        kick.Tick += (_, _) =>
        {
            kick.Stop();
            kick.Dispose();
            try
            {
                _tray.Visible = false;
                _tray.Icon = _icon;
                _tray.Visible = true;
                // Do not auto-pop dashboard — user opens with left-click / menu.
            }
            catch
            {
                // ignore
            }
        };
        kick.Start();

        RefreshStatus();
    }

    private void Tray_MouseClick(object? sender, MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            // Toggle: open if hidden, close if already open
            if (_dash is { Visible: true, IsDisposed: false })
            {
                HideMiniDashboard();
            }
            else
            {
                ShowMiniDashboard();
            }

            return;
        }

        if (e.Button == MouseButtons.Right)
        {
            try
            {
                var mi = typeof(NotifyIcon).GetMethod("ShowContextMenu",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                mi?.Invoke(_tray, null);
            }
            catch
            {
                _menu.Show(Cursor.Position);
            }
        }
    }

    private void ShowMiniDashboard()
    {
        try
        {
            if (_dash is null || _dash.IsDisposed)
            {
                _dash = new MiniDashboardForm(_installDir);
            }

            if (!_dash.Visible)
            {
                _dash.Show();
            }

            _dash.WindowState = FormWindowState.Normal;
            _dash.BringToFront();
            _dash.Activate();
        }
        catch (Exception ex)
        {
            MessageBox.Show("Could not open mini dashboard:\n" + ex.Message,
                "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void HideMiniDashboard()
    {
        try
        {
            if (_dash is { IsDisposed: false })
            {
                _dash.HideDashboard();
            }
        }
        catch
        {
            // ignore
        }
    }

    private void ShowAiConsole()
    {
        try
        {
            if (_aiConsole is null || _aiConsole.IsDisposed)
            {
                _aiConsole = new AiConsoleForm(_installDir);
            }

            if (!_aiConsole.Visible)
            {
                _aiConsole.Show();
            }

            _aiConsole.WindowState = FormWindowState.Normal;
            _aiConsole.BringToFront();
            _aiConsole.Activate();
        }
        catch (Exception ex)
        {
            MessageBox.Show("Could not open AI console:\n" + ex.Message,
                "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void ShowEditCentral()
    {
        try
        {
            using var dlg = new EditCentralServerForm(_installDir);
            dlg.ShowDialog();
            RefreshStatus();
            try { _dash?.RefreshUiPublic(); } catch { /* ignore */ }
        }
        catch (Exception ex)
        {
            MessageBox.Show("Could not open editor:\n" + ex.Message,
                "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void ShowServiceControl()
    {
        try
        {
            using var dlg = new ServiceControlForm();
            dlg.ShowDialog();
            RefreshStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show("Could not open Service Control:\n" + ex.Message,
                "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void InstallAgentService()
    {
        var exe = AgentServiceHelper.FindAgentExe(_installDir);
        if (exe is null)
        {
            MessageBox.Show(
                "NTShield.Agent.exe not found.\nInstall NTShield-Agent-Setup first.",
                "Install Agent service", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (AgentServiceHelper.IsInstalled())
        {
            MessageBox.Show("Service is already registered.\nUse Start / Restart if it is stopped.",
                "Install Agent service", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        AgentServiceHelper.RegisterService(exe, _installDir, owner: null, startAfter: true);
        RefreshStatus();
        try { _dash?.RefreshUiPublic(); } catch { /* ignore */ }
    }

    private void ControlAgentService(string action)
    {
        AgentServiceHelper.Control(action, _installDir);
        if (AgentServiceHelper.TryGetStatus(out var st, out _))
        {
            var tip = action switch
            {
                "start" => "Agent service started",
                "stop" => "Agent service stopped",
                "restart" => "Agent service restarted",
                _ => "Agent service: " + st
            };
            try
            {
                _tray.ShowBalloonTip(2500, "NT Shield", tip,
                    action == "stop" ? ToolTipIcon.Warning : ToolTipIcon.Info);
            }
            catch { /* ignore */ }
        }

        RefreshStatus();
        try { _dash?.RefreshUiPublic(); } catch { /* ignore */ }
    }

    private async Task TestCentralAsync()
    {
        try
        {
            var url = AgentStatusReader.Read(_installDir).CentralUrl;
            if (string.IsNullOrWhiteSpace(url) || url is "(not set)")
            {
                // fall back to appsettings
                var settings = Path.Combine(_installDir, "appsettings.json");
                if (File.Exists(settings))
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(settings));
                    if (doc.RootElement.TryGetProperty("Server", out var s) &&
                        s.TryGetProperty("Url", out var u))
                        url = u.GetString() ?? url;
                }
            }

            if (string.IsNullOrWhiteSpace(url) || url is "(not set)")
            {
                MessageBox.Show("Central URL is not set. Use Edit Central IP / Port first.",
                    "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var baseUrl = url.TrimEnd('/');
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
            using var resp = await http.GetAsync(baseUrl + "/api/v1/health");
            var body = await resp.Content.ReadAsStringAsync();
            if (resp.IsSuccessStatusCode)
            {
                MessageBox.Show(
                    $"OK — Central reachable\n\n{baseUrl}\nHTTP {(int)resp.StatusCode}\n\n{Truncate(body, 200)}",
                    "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show(
                    $"Central responded with error\n\n{baseUrl}\nHTTP {(int)resp.StatusCode}\n\n{Truncate(body, 200)}",
                    "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Cannot reach Central.\n\n" +
                "On agent machines, Server URL must be the Central IP (not localhost).\n\n" +
                ex.Message,
                "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private Icon LoadIcon()
    {
        var size = SystemInformation.SmallIconSize;
        if (size.Width < 16)
        {
            size = new Size(16, 16);
        }

        var paths = new[]
        {
            Path.Combine(_installDir, "NTShield.ico"),
            Path.Combine(AppContext.BaseDirectory, "NTShield.ico"),
            Path.Combine(AppContext.BaseDirectory, "Assets", "NTShield.ico")
        };

        foreach (var p in paths)
        {
            if (!File.Exists(p))
            {
                continue;
            }

            try
            {
                using var fromFile = new Icon(p, size.Width, size.Height);
                return (Icon)fromFile.Clone();
            }
            catch
            {
                try
                {
                    using var fromFile = new Icon(p);
                    using var sized = new Icon(fromFile, size);
                    return (Icon)sized.Clone();
                }
                catch
                {
                    // next
                }
            }
        }

        try
        {
            var exe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exe) && File.Exists(exe))
            {
                using var extracted = Icon.ExtractAssociatedIcon(exe);
                if (extracted is not null)
                {
                    using var sized = new Icon(extracted, size);
                    return (Icon)sized.Clone();
                }
            }
        }
        catch
        {
            // fall through
        }

        return CreateFallbackIcon();
    }

    private static Icon CreateFallbackIcon()
    {
        const int s = 16;
        using var bmp = new Bitmap(s, s, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.Transparent);
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            using (var brush = new SolidBrush(Color.FromArgb(255, 220, 38, 38)))
            {
                g.FillEllipse(brush, 1, 1, s - 3, s - 3);
            }

            using var font = new Font("Segoe UI", 8f, FontStyle.Bold, GraphicsUnit.Pixel);
            using var sf = new StringFormat
            {
                Alignment = StringAlignment.Center,
                LineAlignment = StringAlignment.Center
            };
            g.DrawString("C", font, Brushes.White, new RectangleF(0, 0, s, s), sf);
        }

        var hIcon = bmp.GetHicon();
        try
        {
            using var tmp = Icon.FromHandle(hIcon);
            return (Icon)tmp.Clone();
        }
        finally
        {
            DestroyIcon(hIcon);
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    private static string GetTrayVersion()
    {
        try
        {
            var v = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            return v is null ? "—" : (v.Revision > 0 ? v.ToString(4) : v.ToString(3));
        }
        catch { return "—"; }
    }

    private void RefreshStatus()
    {
        var live = AgentStatusReader.Read(_installDir);
        var trayVer = GetTrayVersion();
        _statusItem.Text = $"Service: {live.ServiceStatus}" +
                           (live.ServiceRunning ? " (monitoring)" : "");
        _hostItem.Text = $"Host: {live.Host}  ·  Agent v{(string.IsNullOrWhiteSpace(live.Version) || live.Version == "—" ? trayVer : live.Version)}";
        _urlItem.Text = $"Central: {Truncate(live.CentralUrl, 42)}";

        var tip = live.ServiceRunning
            ? $"NT Shield v{trayVer} | {live.Host}"
            : $"NT Shield v{trayVer} | {live.ServiceStatus}";
        _tray.Text = Truncate(tip, 63);

        if (!_tray.Visible)
        {
            _tray.Visible = true;
        }
    }

    private static string Truncate(string s, int max)
    {
        if (string.IsNullOrEmpty(s) || s.Length <= max)
        {
            return s;
        }

        return s[..(max - 1)] + "...";
    }

    private static void OpenFolder(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{path}\"",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void ExitTray()
    {
        _timer.Stop();
        try
        {
            if (_dash is { IsDisposed: false })
            {
                _dash.Close();
                _dash.Dispose();
            }
        }
        catch
        {
            // ignore
        }

        try
        {
            if (_aiConsole is { IsDisposed: false })
            {
                _aiConsole.Close();
                _aiConsole.Dispose();
            }
        }
        catch
        {
            // ignore
        }

        _tray.Visible = false;
        _tray.Dispose();
        _icon?.Dispose();
        _menu.Dispose();
        ExitThread();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _timer.Dispose();
            try { _tray.Visible = false; } catch { /* ignore */ }
            _tray.Dispose();
            _icon?.Dispose();
            _menu.Dispose();
            try { _dash?.Dispose(); } catch { /* ignore */ }
            try { _aiConsole?.Dispose(); } catch { /* ignore */ }
        }

        base.Dispose(disposing);
    }
}
