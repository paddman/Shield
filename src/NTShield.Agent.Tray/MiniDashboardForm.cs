using System.Drawing.Drawing2D;
using System.ServiceProcess;

namespace NTShield.Agent.Tray;

/// <summary>
/// Compact always-available panel: shows that the local Agent is monitoring this system.
/// </summary>
internal sealed class MiniDashboardForm : Form
{
    private static readonly Color Navy = Color.FromArgb(6, 27, 59);
    private static readonly Color Brand = Color.FromArgb(15, 104, 255);
    private static readonly Color Success = Color.FromArgb(24, 184, 107);
    private static readonly Color Warning = Color.FromArgb(255, 159, 26);
    private static readonly Color Danger = Color.FromArgb(240, 68, 68);
    private static readonly Color Muted = Color.FromArgb(108, 120, 146);
    private static readonly Color CardBg = Color.White;
    private static readonly Color PageBg = Color.FromArgb(244, 247, 252);

    private readonly string _installDir;
    private readonly System.Windows.Forms.Timer _timer;

    private Label _stateTitle = null!;
    private Label _stateSub = null!;
    private Panel _pulseDot = null!;
    private Label _hostLabel = null!;
    private Label _serviceLabel = null!;
    private Label _centralLabel = null!;
    private Label _modeLabel = null!;
    private Label _kpiEvents = null!;
    private Label _kpiNet = null!;
    private Label _kpiAlerts = null!;
    private Label _kpiQueue = null!;
    private Label _collectorsLabel = null!;
    private Label _lastAlertLabel = null!;
    private Label _footerLabel = null!;
    private Label _uptimeLabel = null!;

    public MiniDashboardForm(string installDir)
    {
        _installDir = installDir;

        var ver = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        var verStr = ver is null ? "" : (ver.Revision > 0 ? ver.ToString(4) : ver.ToString(3));
        Text = string.IsNullOrEmpty(verStr)
            ? "NT Shield — Mini Dashboard"
            : $"NT Shield — Mini Dashboard  v{verStr}";
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        ShowInTaskbar = true;
        TopMost = true;
        BackColor = PageBg;
        Size = new Size(380, 560);
        DoubleBuffered = true;
        Font = new Font("Segoe UI", 9f);
        KeyPreview = true;
        KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Escape)
            {
                HideDashboard();
                e.Handled = true;
            }
        };

        // Place near bottom-right (above taskbar / tray)
        var wa = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1280, 720);
        Location = new Point(wa.Right - Width - 16, wa.Bottom - Height - 16);

        BuildUi();

        _timer = new System.Windows.Forms.Timer { Interval = 2000 };
        _timer.Tick += (_, _) => RefreshUi();
        _timer.Start();
        RefreshUi();
    }

    public void HideDashboard()
    {
        Hide();
    }

    /// <summary>Called from tray after Central IP/Port is edited.</summary>
    public void RefreshUiPublic() => RefreshUi();

    private void BuildUi()
    {
        // Header
        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 72,
            BackColor = Navy,
            Padding = new Padding(14, 12, 10, 10)
        };
        header.MouseDown += DragWindow;

        var title = new Label
        {
            Text = "🛡  NT Shield",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 12f),
            AutoSize = true,
            Location = new Point(14, 12)
        };
        title.MouseDown += DragWindow;

        var sub = new Label
        {
            Text = "Endpoint mini dashboard",
            ForeColor = Color.FromArgb(170, 190, 220),
            Font = new Font("Segoe UI", 8.5f),
            AutoSize = true,
            Location = new Point(42, 40)
        };
        sub.MouseDown += DragWindow;

        // Big visible close (X) top-right
        var close = new Button
        {
            Text = "✕",
            FlatStyle = FlatStyle.Flat,
            ForeColor = Color.White,
            BackColor = Color.FromArgb(200, 50, 50),
            Size = new Size(36, 28),
            Location = new Point(Width - 48, 8),
            Cursor = Cursors.Hand,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
            Font = new Font("Segoe UI", 11f, FontStyle.Bold),
            TabStop = false
        };
        close.FlatAppearance.BorderSize = 0;
        close.Click += (_, _) => HideDashboard();

        var pin = new Button
        {
            Text = "📌",
            FlatStyle = FlatStyle.Flat,
            ForeColor = Color.White,
            BackColor = Color.FromArgb(40, 255, 255, 255),
            Size = new Size(36, 28),
            Location = new Point(Width - 90, 8),
            Cursor = Cursors.Hand,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
            Tag = true
        };
        pin.FlatAppearance.BorderSize = 0;
        pin.Click += (_, _) =>
        {
            TopMost = !TopMost;
            pin.Text = TopMost ? "📌" : "📍";
        };

        header.Controls.Add(title);
        header.Controls.Add(sub);
        header.Controls.Add(close);
        header.Controls.Add(pin);
        Controls.Add(header);

        var body = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(14, 12, 14, 12),
            AutoScroll = true,
            BackColor = PageBg
        };
        Controls.Add(body);
        body.BringToFront();
        header.SendToBack();

        var y = 8;

        // Status card
        var statusCard = MakeCard(body, 12, y, body.ClientSize.Width - 28, 88);
        _pulseDot = new Panel
        {
            Size = new Size(14, 14),
            Location = new Point(16, 22),
            BackColor = Success
        };
        // round-ish via region later
        statusCard.Controls.Add(_pulseDot);

        _stateTitle = new Label
        {
            Text = "MONITORING",
            Font = new Font("Segoe UI Semibold", 14f),
            ForeColor = Navy,
            AutoSize = true,
            Location = new Point(40, 14)
        };
        _stateSub = new Label
        {
            Text = "Agent is actively monitoring this system",
            ForeColor = Muted,
            AutoSize = false,
            Size = new Size(statusCard.Width - 50, 36),
            Location = new Point(40, 44)
        };
        statusCard.Controls.Add(_stateTitle);
        statusCard.Controls.Add(_stateSub);
        y += 100;

        // Host / service
        var infoCard = MakeCard(body, 12, y, body.ClientSize.Width - 28, 108);
        infoCard.Height = 148;
        _hostLabel = InfoLine(infoCard, 12, 12, "Host", "—");
        _serviceLabel = InfoLine(infoCard, 12, 36, "Service", "—");
        _centralLabel = InfoLine(infoCard, 12, 60, "Central", "—");
        _modeLabel = InfoLine(infoCard, 12, 84, "Mode", "DetectOnly");
        var editCentral = new Button
        {
            Text = "Edit Central IP / Port…",
            FlatStyle = FlatStyle.Flat,
            BackColor = Brand,
            ForeColor = Color.White,
            Size = new Size(infoCard.Width - 24, 28),
            Location = new Point(12, 110),
            Cursor = Cursors.Hand,
            Font = new Font("Segoe UI Semibold", 8.5f)
        };
        editCentral.FlatAppearance.BorderSize = 0;
        editCentral.Click += (_, _) =>
        {
            using var dlg = new EditCentralServerForm(_installDir);
            if (dlg.ShowDialog(this) == DialogResult.OK)
                RefreshUi();
        };
        infoCard.Controls.Add(editCentral);
        y += 160;

        // Local service control (this PC)
        var svcCard = MakeCard(body, 12, y, body.ClientSize.Width - 28, 96);
        svcCard.Controls.Add(new Label
        {
            Text = "Service control (this PC)",
            Font = new Font("Segoe UI Semibold", 9f),
            ForeColor = Navy,
            AutoSize = true,
            Location = new Point(12, 10)
        });
        var svcBtnW = (svcCard.Width - 36) / 3;
        var startA = new Button
        {
            Text = "Start Agent",
            FlatStyle = FlatStyle.Flat,
            BackColor = Success,
            ForeColor = Color.White,
            Size = new Size(svcBtnW, 28),
            Location = new Point(12, 36),
            Cursor = Cursors.Hand
        };
        startA.FlatAppearance.BorderSize = 0;
        startA.Click += (_, _) => ControlLocalAgent("start");
        var stopA = new Button
        {
            Text = "Stop Agent",
            FlatStyle = FlatStyle.Flat,
            BackColor = Danger,
            ForeColor = Color.White,
            Size = new Size(svcBtnW, 28),
            Location = new Point(18 + svcBtnW, 36),
            Cursor = Cursors.Hand
        };
        stopA.FlatAppearance.BorderSize = 0;
        stopA.Click += (_, _) => ControlLocalAgent("stop");
        var more = new Button
        {
            Text = "More…",
            FlatStyle = FlatStyle.Flat,
            BackColor = Brand,
            ForeColor = Color.White,
            Size = new Size(svcBtnW, 28),
            Location = new Point(24 + 2 * svcBtnW, 36),
            Cursor = Cursors.Hand
        };
        more.FlatAppearance.BorderSize = 0;
        more.Click += (_, _) =>
        {
            using var dlg = new ServiceControlForm();
            dlg.ShowDialog(this);
            RefreshUi();
        };
        svcCard.Controls.Add(startA);
        svcCard.Controls.Add(stopA);
        svcCard.Controls.Add(more);
        svcCard.Controls.Add(new Label
        {
            Text = "Start/Stop NTShieldAgent · More = any Windows service",
            ForeColor = Muted,
            Font = new Font("Segoe UI", 7.5f),
            AutoSize = true,
            Location = new Point(12, 70)
        });
        y += 108;

        // KPI row
        var kpiW = (body.ClientSize.Width - 28 - 18) / 2;
        var k1 = MakeCard(body, 12, y, kpiW, 72);
        var k2 = MakeCard(body, 18 + kpiW, y, kpiW, 72);
        _kpiEvents = Kpi(k1, "Security events", "0");
        _kpiNet = Kpi(k2, "Network diffs", "0");
        y += 84;

        var k3 = MakeCard(body, 12, y, kpiW, 72);
        var k4 = MakeCard(body, 18 + kpiW, y, kpiW, 72);
        _kpiAlerts = Kpi(k3, "Alerts raised", "0");
        _kpiQueue = Kpi(k4, "Outbound queue", "0");
        y += 84;

        // Collectors
        var colCard = MakeCard(body, 12, y, body.ClientSize.Width - 28, 96);
        var colTitle = new Label
        {
            Text = "Collectors",
            Font = new Font("Segoe UI Semibold", 9.5f),
            ForeColor = Navy,
            Location = new Point(12, 10),
            AutoSize = true
        };
        _collectorsLabel = new Label
        {
            Text = "…",
            ForeColor = Muted,
            Location = new Point(12, 34),
            Size = new Size(colCard.Width - 24, 52)
        };
        colCard.Controls.Add(colTitle);
        colCard.Controls.Add(_collectorsLabel);
        y += 108;

        // Last alert
        var alertCard = MakeCard(body, 12, y, body.ClientSize.Width - 28, 64);
        var alertTitle = new Label
        {
            Text = "Latest detection",
            Font = new Font("Segoe UI Semibold", 9.5f),
            ForeColor = Navy,
            Location = new Point(12, 10),
            AutoSize = true
        };
        _lastAlertLabel = new Label
        {
            Text = "No alerts yet — system quiet",
            ForeColor = Muted,
            Location = new Point(12, 34),
            Size = new Size(alertCard.Width - 24, 20)
        };
        alertCard.Controls.Add(alertTitle);
        alertCard.Controls.Add(_lastAlertLabel);
        y += 76;

        _uptimeLabel = new Label
        {
            Text = "",
            ForeColor = Muted,
            Location = new Point(16, y),
            AutoSize = true
        };
        body.Controls.Add(_uptimeLabel);
        y += 24;

        _footerLabel = new Label
        {
            Text = "Updated —",
            ForeColor = Muted,
            Location = new Point(16, y),
            AutoSize = true
        };
        body.Controls.Add(_footerLabel);
        y += 28;

        // Explicit close button so it's obvious
        var closeBar = new Button
        {
            Text = "Close  (Esc)",
            FlatStyle = FlatStyle.Flat,
            BackColor = Navy,
            ForeColor = Color.White,
            Size = new Size(body.ClientSize.Width - 28, 40),
            Location = new Point(12, y),
            Cursor = Cursors.Hand,
            Font = new Font("Segoe UI Semibold", 10f)
        };
        closeBar.FlatAppearance.BorderSize = 0;
        closeBar.Click += (_, _) => HideDashboard();
        body.Controls.Add(closeBar);

        var hint = new Label
        {
            Text = "ปิดหน้าต่างนี้ได้ — Agent ยัง monitor ต่อ / tray ยังอยู่",
            ForeColor = Muted,
            Location = new Point(16, y + 46),
            AutoSize = true,
            Font = new Font("Segoe UI", 8f)
        };
        body.Controls.Add(hint);

        // Rounded pulse
        var path = new GraphicsPath();
        path.AddEllipse(0, 0, _pulseDot.Width - 1, _pulseDot.Height - 1);
        _pulseDot.Region = new Region(path);

        // Soft shadow / border for form
        Paint += (_, e) =>
        {
            using var pen = new Pen(Color.FromArgb(220, 229, 242), 1);
            e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
        };
    }

    private void ControlLocalAgent(string action)
    {
        AgentServiceHelper.Control(action, _installDir, this);
        RefreshUi();
    }

    private static Panel MakeCard(Control parent, int x, int y, int w, int h)
    {
        var p = new Panel
        {
            Location = new Point(x, y),
            Size = new Size(w, h),
            BackColor = CardBg,
            Padding = new Padding(8)
        };
        p.Paint += (_, e) =>
        {
            using var pen = new Pen(Color.FromArgb(220, 229, 242));
            e.Graphics.DrawRectangle(pen, 0, 0, p.Width - 1, p.Height - 1);
        };
        parent.Controls.Add(p);
        return p;
    }

    private static Label InfoLine(Control parent, int x, int y, string key, string value)
    {
        var k = new Label
        {
            Text = key,
            ForeColor = Muted,
            Font = new Font("Segoe UI", 8.5f),
            Location = new Point(x, y),
            AutoSize = true
        };
        var v = new Label
        {
            Text = value,
            ForeColor = Navy,
            Font = new Font("Segoe UI Semibold", 8.5f),
            Location = new Point(x + 72, y),
            AutoSize = true,
            MaximumSize = new Size(250, 0)
        };
        parent.Controls.Add(k);
        parent.Controls.Add(v);
        return v;
    }

    private static Label Kpi(Control card, string caption, string value)
    {
        var c = new Label
        {
            Text = caption,
            ForeColor = Muted,
            Font = new Font("Segoe UI", 8f),
            Location = new Point(12, 12),
            AutoSize = true
        };
        var v = new Label
        {
            Text = value,
            ForeColor = Navy,
            Font = new Font("Segoe UI Semibold", 16f),
            Location = new Point(12, 32),
            AutoSize = true
        };
        card.Controls.Add(c);
        card.Controls.Add(v);
        return v;
    }

    private void RefreshUi()
    {
        try
        {
            var s = AgentStatusReader.Read(_installDir);
            var monitoring = s.ServiceRunning &&
                             string.Equals(s.State, "Monitoring", StringComparison.OrdinalIgnoreCase);

            _stateTitle.Text = monitoring ? "MONITORING" :
                s.ServiceRunning ? s.State.ToUpperInvariant() : "STOPPED";
            _stateTitle.ForeColor = monitoring ? Success :
                s.ServiceRunning ? Warning : Danger;
            _stateSub.Text = s.Message;
            _pulseDot.BackColor = monitoring ? Success :
                s.ServiceRunning ? Warning : Danger;

            _hostLabel.Text = s.Host;
            _serviceLabel.Text = s.ServiceRunning
                ? $"Running  ·  NTShieldAgent"
                : s.ServiceStatus;
            _serviceLabel.ForeColor = s.ServiceRunning ? Success : Danger;

            var central = string.IsNullOrWhiteSpace(s.CentralUrl) ? "(not set)" : s.CentralUrl;
            if (central.Length > 36)
            {
                central = central[..33] + "...";
            }

            _centralLabel.Text = s.HasStatusFile
                ? $"{central}  {(s.CentralReachable ? "● online" : "○ offline")}"
                : central;
            _centralLabel.ForeColor = s.CentralReachable ? Success : Muted;

            var mode = string.IsNullOrWhiteSpace(s.Mode) ? (s.DetectOnly ? "Ids" : "Ips") : s.Mode;
            var ips = mode.Equals("Ips", StringComparison.OrdinalIgnoreCase);
            _modeLabel.Text = ips
                ? "Mode: IPS (auto block High/Critical)"
                : "Mode: IDS (detect only — no auto block)";
            _modeLabel.ForeColor = ips ? Warning : Brand;

            _kpiEvents.Text = FormatCount(s.EventsCollected);
            _kpiNet.Text = FormatCount(s.ConnectionsCollected);
            _kpiAlerts.Text = FormatCount(s.AlertsRaised);
            _kpiQueue.Text = FormatCount(s.QueueDepth);

            _collectorsLabel.Text =
                Dot(s.SecurityEvents) + " Security events   " +
                Dot(s.NetworkConnections) + " Network\n" +
                Dot(s.Processes) + " Processes   " +
                Dot(s.Services) + " Services\n" +
                Dot(s.ScheduledTasks) + " Scheduled tasks   " +
                Dot(s.Detection) + " Detection engine";

            _lastAlertLabel.Text = string.IsNullOrWhiteSpace(s.LastAlertTitle)
                ? "No alerts yet — system quiet"
                : s.LastAlertTitle!;
            _lastAlertLabel.ForeColor = string.IsNullOrWhiteSpace(s.LastAlertTitle) ? Muted : Danger;

            if (s.StartedAtUtc is { } start)
            {
                var up = DateTimeOffset.UtcNow - start;
                _uptimeLabel.Text = $"Uptime {FormatUptime(up)}  ·  v{s.Version}";
            }
            else
            {
                _uptimeLabel.Text = s.ServiceRunning
                    ? "Status file pending (agent will publish shortly)"
                    : "Start the NTShieldAgent service to begin monitoring";
            }

            var updated = s.UpdatedAtUtc?.ToLocalTime().ToString("HH:mm:ss") ?? "—";
            var dbMb = s.DatabaseSizeBytes > 0
                ? $"  ·  DB {s.DatabaseSizeBytes / (1024.0 * 1024.0):0.0} MB"
                : "";
            var mem = s.WorkingSetBytes > 0
                ? $"  ·  RAM {s.WorkingSetBytes / (1024.0 * 1024.0):0} MB"
                : "";
            _footerLabel.Text = $"Updated {updated}{dbMb}{mem}";
        }
        catch (Exception ex)
        {
            _stateSub.Text = "Status read error: " + ex.Message;
        }
    }

    private static string Dot(bool on) => on ? "●" : "○";

    private static string FormatCount(long n)
    {
        if (n >= 1_000_000)
        {
            return $"{n / 1_000_000.0:0.0}M";
        }

        if (n >= 10_000)
        {
            return $"{n / 1000.0:0.0}k";
        }

        return n.ToString("N0");
    }

    private static string FormatUptime(TimeSpan t)
    {
        if (t.TotalDays >= 1)
        {
            return $"{(int)t.TotalDays}d {t.Hours}h";
        }

        if (t.TotalHours >= 1)
        {
            return $"{(int)t.TotalHours}h {t.Minutes}m";
        }

        return $"{(int)t.TotalMinutes}m {t.Seconds}s";
    }

    private void DragWindow(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left)
        {
            return;
        }

        ReleaseCapture();
        SendMessage(Handle, 0xA1, 0x2, 0);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Hide instead of dispose so tray can reopen quickly (agent keeps running).
        if (e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            HideDashboard();
            return;
        }

        _timer.Stop();
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _timer.Dispose();
        }

        base.Dispose(disposing);
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool ReleaseCapture();

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, int wParam, int lParam);
}
