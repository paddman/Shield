using System.ServiceProcess;

namespace NTShield.Agent.Tray;

/// <summary>
/// Local Windows service start/stop/restart from Agent tray (admin recommended).
/// </summary>
internal sealed class ServiceControlForm : Form
{
    private static readonly Color Navy = Color.FromArgb(6, 27, 59);
    private static readonly Color Brand = Color.FromArgb(15, 104, 255);
    private static readonly Color PageBg = Color.FromArgb(244, 247, 252);
    private static readonly Color Muted = Color.FromArgb(108, 120, 146);

    private readonly TextBox _filterBox;
    private readonly ListBox _list;
    private readonly Label _statusLabel;
    private readonly Label _detailLabel;
    private List<ServiceController> _all = [];
    private readonly List<string> _visibleNames = [];

    public ServiceControlForm()
    {
        Text = "Service Control — this PC";
        FormBorderStyle = FormBorderStyle.Sizable;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = true;
        MaximizeBox = true;
        ShowInTaskbar = true;
        BackColor = PageBg;
        Font = new Font("Segoe UI", 9.5f);
        ClientSize = new Size(520, 480);
        MinimumSize = new Size(440, 360);

        var header = new Panel { Dock = DockStyle.Top, Height = 52, BackColor = Navy };
        header.Controls.Add(new Label
        {
            Text = "Start / Stop / Restart Windows services (local)",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 11f),
            AutoSize = true,
            Location = new Point(16, 14)
        });
        Controls.Add(header);

        var top = new Panel { Dock = DockStyle.Top, Height = 88, Padding = new Padding(14, 10, 14, 6) };
        top.Controls.Add(new Label
        {
            Text = "Filter (name or display):",
            AutoSize = true,
            ForeColor = Muted,
            Location = new Point(14, 8)
        });
        _filterBox = new TextBox { Location = new Point(14, 30), Width = 360, Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top };
        _filterBox.TextChanged += (_, _) => ApplyFilter();
        top.Controls.Add(_filterBox);
        var refresh = new Button
        {
            Text = "Refresh",
            Location = new Point(386, 28),
            Size = new Size(100, 28),
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
            FlatStyle = FlatStyle.Flat,
            BackColor = Brand,
            ForeColor = Color.White,
            Cursor = Cursors.Hand
        };
        refresh.FlatAppearance.BorderSize = 0;
        refresh.Click += (_, _) => Reload();
        top.Controls.Add(refresh);
        top.Controls.Add(new Label
        {
            Text = "Tip: use short Name (e.g. W3SVC) — same as sc.exe. Requires elevation for many services.",
            AutoSize = false,
            Size = new Size(480, 20),
            Location = new Point(14, 62),
            ForeColor = Muted,
            Font = new Font("Segoe UI", 8f),
            Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top
        });
        Controls.Add(top);

        _list = new ListBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 9f),
            IntegralHeight = false
        };
        _list.SelectedIndexChanged += (_, _) => UpdateDetail();
        Controls.Add(_list);

        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 120, Padding = new Padding(14) };
        _detailLabel = new Label
        {
            AutoSize = false,
            Size = new Size(480, 36),
            Location = new Point(14, 8),
            ForeColor = Navy,
            Font = new Font("Consolas", 8.5f),
            Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top
        };
        bottom.Controls.Add(_detailLabel);

        var btnY = 50;
        bottom.Controls.Add(MakeActionBtn("▶ Start", 14, btnY, (_, _) => Run("start")));
        bottom.Controls.Add(MakeActionBtn("■ Stop", 120, btnY, (_, _) => Run("stop")));
        bottom.Controls.Add(MakeActionBtn("↻ Restart", 226, btnY, (_, _) => Run("restart")));
        bottom.Controls.Add(MakeActionBtn("Agent service…", 360, btnY, (_, _) => FocusAgentService()));

        _statusLabel = new Label
        {
            AutoSize = false,
            Size = new Size(480, 22),
            Location = new Point(14, 88),
            ForeColor = Muted,
            Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top
        };
        bottom.Controls.Add(_statusLabel);
        Controls.Add(bottom);

        // Z-order: fill list between top and bottom
        _list.BringToFront();

        Reload();
    }

    private Button MakeActionBtn(string text, int x, int y, EventHandler onClick)
    {
        var b = new Button
        {
            Text = text,
            Location = new Point(x, y),
            Size = new Size(100, 30),
            FlatStyle = FlatStyle.Flat,
            BackColor = Brand,
            ForeColor = Color.White,
            Cursor = Cursors.Hand
        };
        b.FlatAppearance.BorderSize = 0;
        b.Click += onClick;
        return b;
    }

    private void Reload()
    {
        foreach (var s in _all)
        {
            try { s.Dispose(); } catch { /* ignore */ }
        }

        try
        {
            _all = ServiceController.GetServices().OrderBy(s => s.ServiceName, StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (Exception ex)
        {
            _statusLabel.Text = "Cannot list services: " + ex.Message;
            _all = [];
        }

        ApplyFilter();
        _statusLabel.Text = $"Loaded {_all.Count} services";
    }

    private void ApplyFilter()
    {
        var q = (_filterBox.Text ?? "").Trim();
        _list.BeginUpdate();
        _list.Items.Clear();
        _visibleNames.Clear();
        foreach (var s in _all)
        {
            try
            {
                if (q.Length > 0 &&
                    s.ServiceName.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0 &&
                    s.DisplayName.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0)
                    continue;
                var st = SafeStatus(s);
                _list.Items.Add($"{st,-12}  {s.ServiceName}  —  {s.DisplayName}");
                _visibleNames.Add(s.ServiceName);
            }
            catch
            {
                // skip
            }
        }

        _list.EndUpdate();
    }

    private static string SafeStatus(ServiceController s)
    {
        try
        {
            s.Refresh();
            return s.Status.ToString();
        }
        catch
        {
            return "?";
        }
    }

    private ServiceController? SelectedService()
    {
        if (_list.SelectedIndex < 0 || _list.SelectedIndex >= _visibleNames.Count) return null;
        var name = _visibleNames[_list.SelectedIndex];
        return _all.FirstOrDefault(s => s.ServiceName.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    private void UpdateDetail()
    {
        var s = SelectedService();
        if (s is null)
        {
            _detailLabel.Text = "Select a service";
            return;
        }

        try
        {
            s.Refresh();
            _detailLabel.Text = $"Name={s.ServiceName}\nDisplay={s.DisplayName}\nStatus={s.Status}  StartType={s.StartType}";
        }
        catch (Exception ex)
        {
            _detailLabel.Text = ex.Message;
        }
    }

    private void FocusAgentService()
    {
        _filterBox.Text = "NTShieldAgent";
        ApplyFilter();
        if (_list.Items.Count > 0)
            _list.SelectedIndex = 0;
    }

    private void Run(string action)
    {
        var s = SelectedService();
        if (s is null)
        {
            MessageBox.Show(this, "Select a service first.", "Service Control", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        if (MessageBox.Show(this,
                $"{action.ToUpperInvariant()} service?\n\n{s.ServiceName}\n{s.DisplayName}",
                "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            return;

        try
        {
            s.Refresh();
            var timeout = TimeSpan.FromSeconds(45);
            switch (action)
            {
                case "start":
                    if (s.Status is not ServiceControllerStatus.Running and not ServiceControllerStatus.StartPending)
                    {
                        s.Start();
                        s.WaitForStatus(ServiceControllerStatus.Running, timeout);
                    }

                    break;
                case "stop":
                    if (s.Status is not ServiceControllerStatus.Stopped and not ServiceControllerStatus.StopPending)
                    {
                        s.Stop();
                        s.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                    }

                    break;
                case "restart":
                    if (s.Status is not ServiceControllerStatus.Stopped and not ServiceControllerStatus.StopPending)
                    {
                        s.Stop();
                        s.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                    }

                    s.Refresh();
                    s.Start();
                    s.WaitForStatus(ServiceControllerStatus.Running, timeout);
                    break;
            }

            _statusLabel.Text = $"{action} OK — {s.ServiceName} is {SafeStatus(s)}";
            ApplyFilter();
        }
        catch (Exception ex)
        {
            _statusLabel.Text = "Failed: " + ex.Message;
            MessageBox.Show(this,
                ex.Message + "\n\nRun tray as Administrator if access is denied.",
                "Service control failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        foreach (var s in _all)
        {
            try { s.Dispose(); } catch { /* ignore */ }
        }

        base.OnFormClosed(e);
    }
}
