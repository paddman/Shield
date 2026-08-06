using System.Diagnostics;
using System.ServiceProcess;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace NTShield.Agent.Tray;

/// <summary>
/// Simple GUI to edit Central Server IP/host + port (writes Agent appsettings.json and restarts service).
/// </summary>
internal sealed class EditCentralServerForm : Form
{
    private static readonly Color Navy = Color.FromArgb(6, 27, 59);
    private static readonly Color Brand = Color.FromArgb(15, 104, 255);
    private static readonly Color PageBg = Color.FromArgb(244, 247, 252);
    private static readonly Color Muted = Color.FromArgb(108, 120, 146);

    private readonly string _installDir;
    private readonly TextBox _hostBox;
    private readonly NumericUpDown _portBox;
    private readonly CheckBox _httpsBox;
    private readonly CheckBox _untrustedBox;
    private readonly CheckBox _syslogBox;
    private readonly Label _previewLabel;
    private readonly Label _statusLabel;
    private readonly Button _saveBtn;

    public EditCentralServerForm(string installDir)
    {
        _installDir = installDir;

        Text = "Edit Central Server";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterScreen;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = true;
        TopMost = true;
        BackColor = PageBg;
        Font = new Font("Segoe UI", 9.5f);
        ClientSize = new Size(420, 360);
        KeyPreview = true;
        KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Escape) { DialogResult = DialogResult.Cancel; Close(); }
        };

        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 56,
            BackColor = Navy
        };
        var ver = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        var verStr = ver is null ? "" : (ver.Revision > 0 ? ver.ToString(4) : ver.ToString(3));
        header.Controls.Add(new Label
        {
            Text = string.IsNullOrEmpty(verStr)
                ? "Central Server — IP / Port"
                : $"Central Server — IP / Port   (Agent tray v{verStr})",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 11f),
            AutoSize = true,
            Location = new Point(16, 16)
        });
        Controls.Add(header);

        var body = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(20, 16, 20, 12)
        };

        var y = 12;
        body.Controls.Add(MakeLabel("Agent ส่งข้อมูลไปที่ Central (ไม่ต่อ Dashboard โดยตรง)", y, Muted, 8.5f));
        y += 28;

        body.Controls.Add(MakeLabel("IP address or Host name", y, Color.FromArgb(40, 50, 70), 9f));
        y += 22;
        _hostBox = new TextBox
        {
            Location = new Point(20, y),
            Width = 360,
            Font = new Font("Segoe UI", 11f),
            PlaceholderText = "e.g. 10.0.0.5 or sentinel.corp.local"
        };
        body.Controls.Add(_hostBox);
        y += 36;

        body.Controls.Add(MakeLabel("Port", y, Color.FromArgb(40, 50, 70), 9f));
        y += 22;
        _portBox = new NumericUpDown
        {
            Location = new Point(20, y),
            Width = 120,
            Minimum = 1,
            Maximum = 65535,
            Value = 7443,
            Font = new Font("Segoe UI", 11f)
        };
        body.Controls.Add(_portBox);
        y += 40;

        _httpsBox = new CheckBox
        {
            Text = "Use HTTPS (recommended)",
            Checked = true,
            AutoSize = true,
            Location = new Point(20, y)
        };
        body.Controls.Add(_httpsBox);
        y += 26;

        _untrustedBox = new CheckBox
        {
            Text = "Allow self-signed certificate (lab)",
            Checked = true,
            AutoSize = true,
            Location = new Point(20, y)
        };
        body.Controls.Add(_untrustedBox);
        y += 26;

        _syslogBox = new CheckBox
        {
            Text = "Also send alert syslog to same host :5514",
            Checked = true,
            AutoSize = true,
            Location = new Point(20, y)
        };
        body.Controls.Add(_syslogBox);
        y += 30;

        _previewLabel = new Label
        {
            Text = "→ https://…",
            ForeColor = Brand,
            Font = new Font("Segoe UI Semibold", 9.5f),
            AutoSize = true,
            Location = new Point(20, y),
            MaximumSize = new Size(360, 40)
        };
        body.Controls.Add(_previewLabel);
        y += 28;

        _statusLabel = new Label
        {
            Text = "",
            ForeColor = Muted,
            AutoSize = true,
            Location = new Point(20, y),
            MaximumSize = new Size(360, 40)
        };
        body.Controls.Add(_statusLabel);

        Controls.Add(body);

        var footer = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 56,
            BackColor = Color.White,
            Padding = new Padding(12)
        };
        _saveBtn = new Button
        {
            Text = "Save & Restart Agent",
            BackColor = Brand,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(170, 34),
            Location = new Point(230, 10),
            Cursor = Cursors.Hand,
            Font = new Font("Segoe UI Semibold", 9f)
        };
        _saveBtn.FlatAppearance.BorderSize = 0;
        _saveBtn.Click += (_, _) => Save();

        var cancel = new Button
        {
            Text = "Cancel",
            FlatStyle = FlatStyle.Flat,
            Size = new Size(90, 34),
            Location = new Point(130, 10),
            Cursor = Cursors.Hand
        };
        cancel.Click += (_, _) => { DialogResult = DialogResult.Cancel; Close(); };

        footer.Controls.Add(cancel);
        footer.Controls.Add(_saveBtn);
        Controls.Add(footer);

        _hostBox.TextChanged += (_, _) => UpdatePreview();
        _portBox.ValueChanged += (_, _) => UpdatePreview();
        _httpsBox.CheckedChanged += (_, _) => UpdatePreview();

        LoadCurrent();
        UpdatePreview();
        AcceptButton = _saveBtn;
        CancelButton = cancel;
    }

    private static Label MakeLabel(string text, int y, Color color, float size) => new()
    {
        Text = text,
        ForeColor = color,
        Font = new Font("Segoe UI", size),
        AutoSize = true,
        Location = new Point(20, y),
        MaximumSize = new Size(370, 40)
    };

    private string BuildUrl()
    {
        var host = _hostBox.Text.Trim().TrimEnd('/');
        var port = (int)_portBox.Value;
        if (string.IsNullOrWhiteSpace(host))
            return "";

        if (host.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            host.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return host.TrimEnd('/');
        }

        var scheme = _httpsBox.Checked ? "https" : "http";
        return $"{scheme}://{host}:{port}";
    }

    private void UpdatePreview()
    {
        var url = BuildUrl();
        _previewLabel.Text = string.IsNullOrEmpty(url) ? "→ (enter IP / host)" : "→ " + url;
    }

    private string? ResolveAppsettingsPath()
    {
        var candidates = new[]
        {
            Path.Combine(_installDir, "appsettings.json"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "NT Shield Agent", "appsettings.json"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "NT Shield", "Agent", "appsettings.json")
        };
        foreach (var p in candidates)
        {
            if (File.Exists(p)) return p;
        }
        return null;
    }

    private void LoadCurrent()
    {
        try
        {
            var path = ResolveAppsettingsPath();
            if (path is null) return;

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (!doc.RootElement.TryGetProperty("Server", out var server)) return;
            if (!server.TryGetProperty("Url", out var urlEl)) return;
            var url = urlEl.GetString() ?? "";
            if (string.IsNullOrWhiteSpace(url)) return;

            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                _hostBox.Text = uri.Host;
                _portBox.Value = uri.IsDefaultPort
                    ? (uri.Scheme == "https" ? 7443 : 80)
                    : uri.Port;
                _httpsBox.Checked = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                _hostBox.Text = url;
            }

            if (server.TryGetProperty("AllowUntrustedServerCertificate", out var ut) &&
                ut.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                _untrustedBox.Checked = ut.GetBoolean();
            }

            if (server.TryGetProperty("SyslogEnabled", out var se) && se.ValueKind == JsonValueKind.True)
                _syslogBox.Checked = true;
        }
        catch
        {
            // keep defaults
        }
    }

    private void Save()
    {
        var host = _hostBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(host))
        {
            MessageBox.Show(this, "Please enter Central Server IP or host name.",
                "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            _hostBox.Focus();
            return;
        }

        var url = BuildUrl();
        if (string.IsNullOrWhiteSpace(url))
        {
            MessageBox.Show(this, "Invalid server address.", "NT Shield",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var path = ResolveAppsettingsPath();
        if (path is null)
        {
            MessageBox.Show(this,
                "Cannot find appsettings.json under Agent install folder:\n" + _installDir,
                "NT Shield", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        _saveBtn.Enabled = false;
        _statusLabel.ForeColor = Muted;
        _statusLabel.Text = "Saving…";
        Application.DoEvents();

        try
        {
            var text = File.ReadAllText(path);
            var root = JsonNode.Parse(text) as JsonObject
                       ?? throw new InvalidOperationException("Invalid appsettings.json");
            var server = root["Server"] as JsonObject;
            if (server is null)
            {
                server = new JsonObject();
                root["Server"] = server;
            }

            server["Url"] = url;
            server["AllowUntrustedServerCertificate"] = _untrustedBox.Checked;

            if (_syslogBox.Checked)
            {
                var syslogHost = host;
                if (Uri.TryCreate(url, UriKind.Absolute, out var u))
                    syslogHost = u.Host;

                server["SyslogEnabled"] = true;
                server["SyslogHost"] = syslogHost;
                server["SyslogPort"] = 5514;
            }

            var opts = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(path, root.ToJsonString(opts));

            _statusLabel.Text = "Restarting Agent service…";
            Application.DoEvents();
            RestartAgentService();

            _statusLabel.ForeColor = Color.FromArgb(24, 184, 107);
            _statusLabel.Text = "Saved. Agent → " + url;

            MessageBox.Show(this,
                "Central server updated.\n\n" +
                "Agent URL:\n" + url + "\n\n" +
                "Set the SAME URL in Dashboard → Settings.",
                "NT Shield",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);

            DialogResult = DialogResult.OK;
            Close();
        }
        catch (Exception ex)
        {
            _statusLabel.ForeColor = Color.FromArgb(240, 68, 68);
            _statusLabel.Text = "Save failed.";
            MessageBox.Show(this,
                "Could not save Central settings:\n" + ex.Message +
                "\n\nTry running tray as Administrator, or:\n" +
                "  Installer\\set-agent-central-url.ps1 -ServerHost ... -Port ...",
                "NT Shield",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        finally
        {
            _saveBtn.Enabled = true;
        }
    }

    private static void RestartAgentService()
    {
        const string name = "NTShieldAgent";
        try
        {
            using var sc = new ServiceController(name);
            if (sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
            {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(25));
            }

            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(25));
        }
        catch
        {
            // Fallback: sc.exe (may still fail without elevation)
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"stop {name}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                })?.WaitForExit(15000);
                Thread.Sleep(1500);
                Process.Start(new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"start {name}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                })?.WaitForExit(15000);
            }
            catch
            {
                // ignore — config is saved; user can restart service manually
            }
        }
    }
}
