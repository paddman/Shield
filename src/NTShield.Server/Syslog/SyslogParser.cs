using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace NTShield.Server.Syslog;

public sealed class ParsedSyslogMessage
{
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Host { get; set; } = string.Empty;
    public string AppName { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string Raw { get; set; } = string.Empty;
    public int? Priority { get; set; }
    public string? SourceIp { get; set; }
}

public static partial class SyslogParser
{
    // RFC5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED MSG
    [GeneratedRegex(@"^<(?<pri>\d{1,3})>(?<ver>\d)\s+(?<ts>\S+)\s+(?<host>\S+)\s+(?<app>\S+)\s+(?<proc>\S+)\s+(?<msgid>\S+)\s+(?<rest>.*)$",
        RegexOptions.Compiled)]
    private static partial Regex Rfc5424();

    // RFC3164: <PRI>Mon DD HH:MM:SS HOST TAG: MSG
    [GeneratedRegex(@"^<(?<pri>\d{1,3})>(?<mon>[A-Z][a-z]{2})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<tag>[^:\s]+)[:\s]+(?<msg>.*)$",
        RegexOptions.Compiled)]
    private static partial Regex Rfc3164();

    public static ParsedSyslogMessage Parse(string raw, IPEndPoint? remote)
    {
        raw = raw.Trim().Trim('\0');
        var result = new ParsedSyslogMessage
        {
            Raw = raw,
            SourceIp = remote?.Address.ToString(),
            Host = remote?.Address.ToString() ?? "unknown",
            Message = raw
        };

        var m5424 = Rfc5424().Match(raw);
        if (m5424.Success)
        {
            result.Priority = int.Parse(m5424.Groups["pri"].Value);
            if (DateTimeOffset.TryParse(m5424.Groups["ts"].Value, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var ts))
            {
                result.TimestampUtc = ts.ToUniversalTime();
            }

            result.Host = NullDash(m5424.Groups["host"].Value) ?? result.Host;
            result.AppName = NullDash(m5424.Groups["app"].Value) ?? "";
            var rest = m5424.Groups["rest"].Value;
            // strip structured data -
            if (rest.StartsWith('['))
            {
                var end = rest.IndexOf("] ", StringComparison.Ordinal);
                result.Message = end > 0 ? rest[(end + 2)..] : rest;
            }
            else if (rest.StartsWith("- "))
            {
                result.Message = rest[2..];
            }
            else
            {
                result.Message = rest;
            }

            return result;
        }

        var m3164 = Rfc3164().Match(raw);
        if (m3164.Success)
        {
            result.Priority = int.Parse(m3164.Groups["pri"].Value);
            result.Host = m3164.Groups["host"].Value;
            result.AppName = m3164.Groups["tag"].Value;
            result.Message = m3164.Groups["msg"].Value;
            var year = DateTime.UtcNow.Year;
            var stamp = $"{m3164.Groups["mon"].Value} {m3164.Groups["day"].Value} {year} {m3164.Groups["time"].Value}";
            if (DateTime.TryParseExact(stamp, "MMM d yyyy HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var dt) ||
                DateTime.TryParseExact(stamp, "MMM dd yyyy HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out dt))
            {
                result.TimestampUtc = new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc));
            }

            return result;
        }

        // Fallback: plain text / CEF without PRI
        result.Message = raw;
        if (raw.Contains("CEF:", StringComparison.OrdinalIgnoreCase))
        {
            result.AppName = "CEF";
        }

        return result;
    }

    private static string? NullDash(string s) =>
        string.IsNullOrWhiteSpace(s) || s == "-" ? null : s;
}
