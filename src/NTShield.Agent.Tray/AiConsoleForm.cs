using System.Text;

namespace NTShield.Agent.Tray;

/// <summary>
/// Desktop SOC view for Brain and LLM output. It is read-only: response actions
/// remain approval-gated in Central and are not executed from this window.
/// </summary>
internal sealed class AiConsoleForm : Form
{
    private static readonly Color Navy = Color.FromArgb(6, 27, 59);
    private static readonly Color Brand = Color.FromArgb(15, 104, 255);
    private static readonly Color Success = Color.FromArgb(24, 184, 107);
    private static readonly Color Warning = Color.FromArgb(224, 135, 16);
    private static readonly Color Danger = Color.FromArgb(220, 56, 56);
    private static readonly Color Muted = Color.FromArgb(102, 116, 142);
    private static readonly Color PageBg = Color.FromArgb(244, 247, 252);
    private static readonly Color CardBg = Color.White;

    private readonly string _installDir;
    private readonly AiConsoleConfig _config;
    private readonly AiRealtimeClient _client;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly Button _refreshButton;
    private readonly Label _brainValue;
    private readonly Label _llmValue;
    private readonly Label _agentValue;
    private readonly Label _analysisValue;
    private readonly Label _statusLabel;
    private readonly Label _updatedLabel;
    private readonly DataGridView _analysisGrid;
    private readonly RichTextBox _details;
    private IReadOnlyList<AiAnalysisItem> _analyses = [];
    private bool _refreshing;

    public AiConsoleForm(string installDir)
    {
        _installDir = installDir;
        _config = AiConsoleConfig.Load(installDir);
        _client = new AiRealtimeClient(_config);

        Text = "NT Shield AI Realtime Console";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(900, 600);
        Size = new Size(1120, 760);
        BackColor = PageBg;
        Font = new Font("Segoe UI", 9f);
        KeyPreview = true;
        KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.F5)
            {
                _ = RefreshAsync();
                e.Handled = true;
            }
        };

        _brainValue = new Label();
        _llmValue = new Label();
        _agentValue = new Label();
        _analysisValue = new Label();
        _statusLabel = new Label();
        _updatedLabel = new Label();
        _refreshButton = new Button
        {
            Text = "Refresh now",
            AutoSize = true,
            FlatStyle = FlatStyle.Flat,
            BackColor = Brand,
            ForeColor = Color.White,
            Cursor = Cursors.Hand,
            Padding = new Padding(12, 4, 12, 4)
        };
        _refreshButton.FlatAppearance.BorderSize = 0;
        _refreshButton.Click += async (_, _) => await RefreshAsync();

        _analysisGrid = new DataGridView
        {
            Dock = DockStyle.Fill,
            BackgroundColor = Color.White,
            BorderStyle = BorderStyle.None,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            ReadOnly = true,
            MultiSelect = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoGenerateColumns = false,
            RowHeadersVisible = false,
            ColumnHeadersHeight = 34,
            AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None
        };
        _analysisGrid.EnableHeadersVisualStyles = false;
        _analysisGrid.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = Navy,
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 9f),
            Alignment = DataGridViewContentAlignment.MiddleLeft
        };
        _analysisGrid.DefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = Color.White,
            ForeColor = Navy,
            SelectionBackColor = Color.FromArgb(222, 235, 255),
            SelectionForeColor = Navy,
            Padding = new Padding(6, 4, 6, 4)
        };
        _analysisGrid.AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = Color.FromArgb(249, 251, 255)
        };
        _analysisGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "time", HeaderText = "Time", Width = 90
        });
        _analysisGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "risk", HeaderText = "Risk", Width = 56
        });
        _analysisGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "classification", HeaderText = "Classification", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill
        });
        _analysisGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "incident", HeaderText = "Incident", Width = 180
        });
        _analysisGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "model", HeaderText = "Model", Width = 150
        });
        _analysisGrid.SelectionChanged += (_, _) => ShowSelectedAnalysis();
        _analysisGrid.CellFormatting += (_, e) =>
        {
            if (e.RowIndex >= 0 && e.ColumnIndex == 1 &&
                e.Value is int score)
            {
                e.CellStyle.ForeColor = score >= 85 ? Danger : score >= 65 ? Warning : Brand;
                e.CellStyle.Font = new Font("Segoe UI Semibold", 9f);
            }
        };

        _details = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            BackColor = CardBg,
            ForeColor = Navy,
            Font = new Font("Segoe UI", 9.5f),
            DetectUrls = false,
            Padding = new Padding(12)
        };

        BuildUi();
        _timer = new System.Windows.Forms.Timer { Interval = _config.RefreshSeconds * 1000 };
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        Shown += async (_, _) => await RefreshAsync();
    }

    private void BuildUi()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            BackColor = PageBg,
            ColumnCount = 1,
            RowCount = 4,
            Padding = new Padding(16)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 78));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 92));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var header = new Panel { Dock = DockStyle.Fill, BackColor = Navy, Padding = new Padding(18, 12, 18, 8) };
        header.Controls.Add(new Label
        {
            Text = "NT Shield AI Console",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 17f),
            AutoSize = true,
            Location = new Point(18, 10)
        });
        header.Controls.Add(new Label
        {
            Text = "Realtime analyst stream · evidence-grounded · approval-gated",
            ForeColor = Color.FromArgb(179, 201, 232),
            Font = new Font("Segoe UI", 9f),
            AutoSize = true,
            Location = new Point(20, 45)
        });
        root.Controls.Add(header, 0, 0);

        var status = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 4,
            RowCount = 1,
            BackColor = PageBg,
            Margin = new Padding(0, 10, 0, 0)
        };
        for (var i = 0; i < 4; i++) status.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        status.Controls.Add(StatusCard("BRAIN", _brainValue), 0, 0);
        status.Controls.Add(StatusCard("LLM MODEL", _llmValue), 1, 0);
        status.Controls.Add(StatusCard("LOCAL AGENT", _agentValue), 2, 0);
        status.Controls.Add(StatusCard("ANALYSES", _analysisValue), 3, 0);
        root.Controls.Add(status, 0, 1);

        var toolbar = new Panel { Dock = DockStyle.Fill, BackColor = PageBg };
        toolbar.Controls.Add(_refreshButton);
        toolbar.Controls.Add(new Label
        {
            Text = "F5 or auto refresh",
            ForeColor = Muted,
            AutoSize = true,
            Location = new Point(112, 9)
        });
        _statusLabel.Text = "Starting AI console…";
        _statusLabel.ForeColor = Muted;
        _statusLabel.AutoSize = true;
        _statusLabel.Location = new Point(270, 9);
        toolbar.Controls.Add(_statusLabel);
        _updatedLabel.Text = "Updated —";
        _updatedLabel.ForeColor = Muted;
        _updatedLabel.AutoSize = true;
        _updatedLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _updatedLabel.Location = new Point(Width - 180, 9);
        toolbar.Controls.Add(_updatedLabel);
        root.Controls.Add(toolbar, 0, 2);

        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            SplitterDistance = 590,
            BackColor = PageBg,
            Panel1MinSize = 380,
            Panel2MinSize = 320
        };
        var listCard = new Panel { Dock = DockStyle.Fill, BackColor = CardBg, Padding = new Padding(10) };
        listCard.Controls.Add(_analysisGrid);
        split.Panel1.Controls.Add(listCard);
        var detailsCard = new Panel { Dock = DockStyle.Fill, BackColor = CardBg, Padding = new Padding(10) };
        detailsCard.Controls.Add(_details);
        split.Panel2.Controls.Add(detailsCard);
        root.Controls.Add(split, 0, 3);
        Controls.Add(root);
    }

    private static Panel StatusCard(string caption, Label value)
    {
        var card = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = CardBg,
            Margin = new Padding(0, 0, 8, 0),
            Padding = new Padding(12, 8, 8, 6)
        };
        card.Paint += (_, e) =>
        {
            using var pen = new Pen(Color.FromArgb(218, 226, 239));
            e.Graphics.DrawRectangle(pen, 0, 0, card.Width - 1, card.Height - 1);
        };
        card.Controls.Add(new Label
        {
            Text = caption,
            ForeColor = Muted,
            Font = new Font("Segoe UI Semibold", 8f),
            AutoSize = true,
            Location = new Point(12, 9)
        });
        value.Text = "—";
        value.ForeColor = Navy;
        value.Font = new Font("Segoe UI Semibold", 13f);
        value.AutoSize = true;
        value.Location = new Point(12, 30);
        card.Controls.Add(value);
        return card;
    }

    private async Task RefreshAsync()
    {
        if (_refreshing || IsDisposed) return;
        _refreshing = true;
        _refreshButton.Enabled = false;
        try
        {
            var agent = AgentStatusReader.Read(_installDir);
            var snapshot = await _client.ReadAsync(CancellationToken.None);
            _analyses = snapshot.Analyses;

            _brainValue.Text = snapshot.BrainReachable ? "ONLINE" : "OFFLINE";
            _brainValue.ForeColor = snapshot.BrainReachable ? Success : Danger;
            _llmValue.Text = snapshot.LlmReachable ? Truncate(snapshot.LlmModel, 18) : "UNAVAILABLE";
            _llmValue.ForeColor = snapshot.LlmReachable ? Success : Warning;
            _agentValue.Text = agent.ServiceRunning
                ? (agent.CentralReachable ? "MONITORING" : "LOCAL ONLY")
                : "STOPPED";
            _agentValue.ForeColor = agent.ServiceRunning && agent.CentralReachable ? Success :
                agent.ServiceRunning ? Warning : Danger;
            _analysisValue.Text = _analyses.Count.ToString("N0");
            _analysisValue.ForeColor = _analyses.Count > 0 ? Brand : Muted;

            _statusLabel.Text = snapshot.StatusMessage +
                                $"  ·  Brain {Truncate(snapshot.BrainUrl, 42)}";
            _statusLabel.ForeColor = snapshot.BrainReachable ? Muted : Danger;
            _updatedLabel.Text = $"Updated {snapshot.FetchedAtUtc.ToLocalTime():HH:mm:ss}";
            PopulateGrid();
            if (_analyses.Count == 0)
            {
                _details.Text = BuildEmptyDetails(snapshot, agent);
            }
            else if (_analysisGrid.SelectedRows.Count == 0)
            {
                _analysisGrid.Rows[0].Selected = true;
                ShowSelectedAnalysis();
            }
        }
        catch (Exception ex)
        {
            _statusLabel.Text = "Refresh failed: " + ex.Message;
            _statusLabel.ForeColor = Danger;
        }
        finally
        {
            _refreshing = false;
            _refreshButton.Enabled = true;
        }
    }

    private void PopulateGrid()
    {
        var previous = _analysisGrid.SelectedRows.Count > 0
            ? _analysisGrid.SelectedRows[0].Cells["incident"].Value?.ToString()
            : null;
        _analysisGrid.Rows.Clear();
        foreach (var analysis in _analyses)
        {
            var row = _analysisGrid.Rows.Add(
                analysis.CreatedAtUtc?.ToLocalTime().ToString("HH:mm:ss") ?? "—",
                analysis.RiskScore,
                analysis.Classification,
                analysis.IncidentId,
                analysis.Model);
            _analysisGrid.Rows[row].Tag = analysis;
        }

        if (_analysisGrid.Rows.Count == 0) return;
        var selected = -1;
        if (!string.IsNullOrWhiteSpace(previous))
        {
            for (var i = 0; i < _analysisGrid.Rows.Count; i++)
            {
                if (string.Equals(_analysisGrid.Rows[i].Cells["incident"].Value?.ToString(), previous,
                        StringComparison.OrdinalIgnoreCase))
                {
                    selected = i;
                    break;
                }
            }
        }
        _analysisGrid.Rows[selected >= 0 ? selected : 0].Selected = true;
    }

    private void ShowSelectedAnalysis()
    {
        if (_analysisGrid.SelectedRows.Count == 0 || _analysisGrid.SelectedRows[0].Tag is not AiAnalysisItem analysis)
            return;

        var sb = new StringBuilder();
        sb.AppendLine(analysis.Classification);
        sb.AppendLine(new string('─', 54));
        sb.AppendLine($"Incident: {analysis.IncidentId}");
        sb.AppendLine($"Risk score: {analysis.RiskScore}/100    Confidence: {analysis.Confidence:P0}");
        sb.AppendLine($"Model: {analysis.Model}    Mode: {analysis.AnalysisMode}    LLM calls: {analysis.LlmCalls}");
        sb.AppendLine(analysis.DeterministicFallback
            ? "Safety note: deterministic fallback; LLM output was not used."
            : "Safety note: LLM result bounded by deterministic risk and evidence guardrails.");
        sb.AppendLine();
        sb.AppendLine("THAI SUMMARY");
        sb.AppendLine(string.IsNullOrWhiteSpace(analysis.SummaryThai) ? "No Thai summary returned." : analysis.SummaryThai);
        if (!string.IsNullOrWhiteSpace(analysis.SummaryEnglish))
        {
            sb.AppendLine();
            sb.AppendLine("ENGLISH SUMMARY");
            sb.AppendLine(analysis.SummaryEnglish);
        }
        AppendSection(sb, "ATTACK CHAIN", analysis.AttackChain);
        AppendSection(sb, "MITRE TECHNIQUES", analysis.MitreTechniques);
        AppendSection(sb, "RECOMMENDED ACTIONS (HUMAN APPROVAL REQUIRED)", analysis.RecommendedActions);
        AppendSection(sb, "EVIDENCE REFERENCES", analysis.Evidence);
        AppendSection(sb, "UNKNOWN / NEEDS FOLLOW-UP", analysis.Unknowns);
        _details.Text = sb.ToString();
    }

    private static void AppendSection(StringBuilder sb, string title, IReadOnlyList<string> values)
    {
        sb.AppendLine();
        sb.AppendLine(title);
        if (values.Count == 0)
        {
            sb.AppendLine("—");
            return;
        }

        foreach (var value in values.Take(12)) sb.AppendLine("• " + value);
    }

    private static string BuildEmptyDetails(AiRealtimeSnapshot snapshot, AgentLiveStatus agent) =>
        $"No AI analyses to display yet.\n\n" +
        $"Brain: {(snapshot.BrainReachable ? "online" : "offline")}\n" +
        $"LLM: {(snapshot.LlmReachable ? snapshot.LlmModel : "not reachable")}\n" +
        $"Agent: {(agent.ServiceRunning ? "monitoring" : "stopped")}\n\n" +
        "When Brain is online and configured, this window will show the latest " +
        "evidence-grounded analysis. The local Agent continues monitoring even " +
        "when the AI service is unavailable.";

    private static string Truncate(string value, int max) =>
        string.IsNullOrWhiteSpace(value) ? "—" : value.Length <= max ? value : value[..Math.Max(0, max - 3)] + "...";

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        _timer.Stop();
        _client.Dispose();
        base.OnFormClosing(e);
    }
}
