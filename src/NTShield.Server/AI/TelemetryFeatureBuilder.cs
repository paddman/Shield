using System.Net;
using NTShield.Shared.Contracts;
using NTShield.Shared.Enums;

namespace NTShield.Server.AI;

/// <summary>
/// Converts one agent telemetry batch into stable numeric features for the
/// Phase 1 per-asset baseline. No raw event content or identifiers are sent.
/// </summary>
public sealed class TelemetryFeatureBuilder
{
    public IReadOnlyDictionary<string, double> Build(AgentIngestBatch batch)
    {
        var events = batch.SecurityEvents ?? [];
        var connections = batch.NetworkConnections ?? [];
        var processes = batch.Processes ?? [];
        var services = batch.Services ?? [];
        var scheduledTasks = batch.ScheduledTasks ?? [];
        var alerts = batch.Alerts ?? [];

        var sourceAddresses = events
            .Select(item => item.SourceIp)
            .Concat(alerts.Select(item => item.SourceIp))
            .Where(IsAddress)
            .Select(item => item!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var destinationAddresses = events
            .Select(item => item.DestinationIp)
            .Concat(alerts.Select(item => item.DestinationIp))
            .Concat(connections.Select(item => item.RemoteAddress))
            .Where(IsAddress)
            .Select(item => item!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var features = new Dictionary<string, double>(StringComparer.Ordinal)
        {
            ["security_events"] = events.Count,
            ["network_connections"] = connections.Count,
            ["new_network_connections"] = connections.Count(item => item.IsNew),
            ["closed_network_connections"] = connections.Count(item => item.IsClosed),
            ["unique_remote_addresses"] = destinationAddresses.Count,
            ["unique_external_remote_addresses"] = destinationAddresses.Count(IsPublicAddress),
            ["unique_remote_ports"] = connections.Select(item => item.RemotePort).Where(item => item > 0).Distinct().Count(),
            ["processes"] = processes.Count,
            ["unique_process_names"] = processes.Select(item => item.ProcessName).Where(HasText).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            ["services"] = services.Count,
            ["scheduled_tasks"] = scheduledTasks.Count,
            ["detection_alerts"] = alerts.Count,
            ["high_or_critical_alerts"] = alerts.Count(item => item.Severity >= Severity.High),
            ["failed_logons"] = events.Count(item => item.EventId == 4625),
            ["successful_logons"] = events.Count(item => item.EventId == 4624),
            ["explicit_credential_events"] = events.Count(item => item.EventId == 4648),
            ["process_create_events"] = events.Count(item => item.EventId == 4688),
            ["service_install_events"] = events.Count(item => item.EventId == 7045),
            ["unique_source_addresses"] = sourceAddresses.Count,
            ["unique_external_source_addresses"] = sourceAddresses.Count(IsPublicAddress),
            ["unique_users"] = events
                .SelectMany(item => new[] { item.Username, item.TargetUserName })
                .Where(HasText)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            ["privileged_logons"] = events.Count(item => item.LogonType is 2 or 10),
            ["telemetry_records"] = events.Count + connections.Count + processes.Count + services.Count + scheduledTasks.Count + alerts.Count
        };

        return features;
    }

    private static bool HasText(string? value) => !string.IsNullOrWhiteSpace(value);

    private static bool IsAddress(string? value) =>
        !string.IsNullOrWhiteSpace(value) && IPAddress.TryParse(value, out _);

    private static bool IsPublicAddress(string value)
    {
        if (!IPAddress.TryParse(value, out var address)) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)) return false;

        var bytes = address.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return bytes[0] switch
            {
                10 or 127 => false,
                169 when bytes[1] == 254 => false,
                172 when bytes[1] is >= 16 and <= 31 => false,
                192 when bytes[1] == 168 => false,
                100 when bytes[1] is >= 64 and <= 127 => false,
                _ => true
            };
        }

        // fc00::/7 unique-local and fe80::/10 link-local are not public.
        return (bytes[0] & 0xFE) != 0xFC && !(bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80);
    }
}
