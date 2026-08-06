using System.Net;
using System.Net.Sockets;
using System.Text;
using NTShield.Core.Configuration;
using NTShield.Shared.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NTShield.Transport;

/// <summary>
/// Forwards detection alerts as RFC5424-ish syslog UDP to Central (or SIEM).
/// </summary>
public sealed class SyslogForwarder
{
    private readonly CentralServerOptions _options;
    private readonly ILogger<SyslogForwarder> _logger;

    public SyslogForwarder(IOptions<CentralServerOptions> options, ILogger<SyslogForwarder> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public bool Enabled => _options.SyslogEnabled && !string.IsNullOrWhiteSpace(_options.SyslogHost);

    public async Task SendAlertAsync(DetectionAlert alert, string computerName, CancellationToken ct)
    {
        if (!Enabled)
        {
            return;
        }

        try
        {
            // <134> = local0.notice
            var pri = 134;
            var ts = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var host = string.IsNullOrWhiteSpace(computerName) ? Environment.MachineName : computerName;
            var app = string.IsNullOrWhiteSpace(_options.SyslogAppName) ? "NTShield" : _options.SyslogAppName;
            var msg =
                $"NTShield-ALERT RuleId={alert.RuleId} Severity={alert.Severity} Title={Sanitize(alert.Title)} " +
                $"SourceIp={alert.SourceIp ?? "-"} DestIp={alert.DestinationIp ?? "-"} User={alert.Username ?? "-"} " +
                $"Host={host} AlertId={alert.AlertId} Desc={Sanitize(alert.Description)}";

            var line = $"<{pri}>1 {ts} {host} {app} - - - {msg}";
            var bytes = Encoding.UTF8.GetBytes(line);

            using var udp = new UdpClient();
            await udp.SendAsync(bytes, bytes.Length, _options.SyslogHost, _options.SyslogPort);
            _logger.LogDebug("Syslog alert sent to {Host}:{Port} rule={Rule}", _options.SyslogHost, _options.SyslogPort, alert.RuleId);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Syslog forward failed");
        }
    }

    private static string Sanitize(string? s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return "-";
        }

        return s.Replace('\n', ' ').Replace('\r', ' ').Replace('|', '/');
    }
}
