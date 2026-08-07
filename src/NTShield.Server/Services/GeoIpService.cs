using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace NTShield.Server.Services;

public sealed record GeoIpLookupRequest(IReadOnlyList<string>? Ips);

public sealed record GeoIpLocation(
    string Ip,
    bool Success,
    bool IsPrivate,
    string? Country,
    string? CountryCode,
    string? Region,
    string? City,
    double? Latitude,
    double? Longitude,
    string Provider,
    bool Approximate,
    string? Error = null);

/// <summary>
/// Resolves public attack-source IPs to approximate country/city coordinates.
/// Results are cached so the dashboard does not repeatedly disclose the same IP
/// to the external provider or consume the provider's free request allowance.
/// </summary>
public sealed class GeoIpService
{
    private const int MaxIpsPerRequest = 20;
    private static readonly TimeSpan SuccessTtl = TimeSpan.FromDays(7);
    private static readonly TimeSpan FailureTtl = TimeSpan.FromMinutes(15);
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<GeoIpService> _logger;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

    public GeoIpService(IHttpClientFactory httpClientFactory, ILogger<GeoIpService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<IReadOnlyList<GeoIpLocation>> LookupAsync(
        IEnumerable<string>? requestedIps,
        CancellationToken cancellationToken)
    {
        var ips = (requestedIps ?? [])
            .Select(NormalizeIp)
            .Where(ip => ip is not null)
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(MaxIpsPerRequest)
            .ToArray();

        var results = new List<GeoIpLocation>(ips.Length);
        foreach (var ip in ips)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IPAddress.TryParse(ip, out var address))
            {
                results.Add(Failed(ip, "invalid_ip"));
                continue;
            }

            if (!IsPublic(address))
            {
                results.Add(new GeoIpLocation(
                    ip, true, true, null, null, null, null, null, null,
                    "local", true));
                continue;
            }

            results.Add(await LookupPublicAsync(ip, cancellationToken));
        }

        return results;
    }

    private async Task<GeoIpLocation> LookupPublicAsync(string ip, CancellationToken cancellationToken)
    {
        if (_cache.TryGetValue(ip, out var cached) && cached.ExpiresAtUtc > DateTimeOffset.UtcNow)
            return cached.Location;

        GeoIpLocation result;
        try
        {
            using var client = _httpClientFactory.CreateClient("geoip");
            var fields = "success,message,ip,country,country_code,region,city,latitude,longitude";
            using var response = await client.GetAsync(
                $"{Uri.EscapeDataString(ip)}?fields={Uri.EscapeDataString(fields)}",
                cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                result = Failed(ip, $"provider_http_{(int)response.StatusCode}");
            }
            else
            {
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
                var root = document.RootElement;
                var success = GetBoolean(root, "success");
                var latitude = GetDouble(root, "latitude");
                var longitude = GetDouble(root, "longitude");
                result = success && latitude is not null && longitude is not null
                    ? new GeoIpLocation(
                        ip,
                        true,
                        false,
                        GetString(root, "country"),
                        GetString(root, "country_code"),
                        GetString(root, "region"),
                        GetString(root, "city"),
                        latitude,
                        longitude,
                        "ipwho.is",
                        true)
                    : Failed(ip, GetString(root, "message") ?? "provider_no_location");
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            result = Failed(ip, "provider_timeout");
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException)
        {
            _logger.LogWarning("GeoIP lookup failed for {Ip}: {Error}", ip, ex.Message);
            result = Failed(ip, "provider_unavailable");
        }

        _cache[ip] = new CacheEntry(
            result,
            DateTimeOffset.UtcNow + (result.Success ? SuccessTtl : FailureTtl));
        return result;
    }

    private static GeoIpLocation Failed(string ip, string error) =>
        new(ip, false, false, null, null, null, null, null, null, "ipwho.is", true, error);

    private static string? NormalizeIp(string? value)
    {
        var candidate = value?.Trim();
        if (string.IsNullOrWhiteSpace(candidate)) return null;

        if (candidate.StartsWith('['))
        {
            var close = candidate.IndexOf(']');
            if (close > 1) candidate = candidate[1..close];
        }
        else
        {
            var colon = candidate.LastIndexOf(':');
            if (colon > 0 && candidate.Count(ch => ch == ':') == 1 &&
                int.TryParse(candidate[(colon + 1)..], out _))
            {
                candidate = candidate[..colon];
            }
        }

        return candidate;
    }

    private static bool IsPublic(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return false;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return !address.IsIPv6LinkLocal &&
                   !address.IsIPv6SiteLocal &&
                   !address.IsIPv6Multicast &&
                   !address.IsIPv6UniqueLocal &&
                   !address.Equals(IPAddress.IPv6Any) &&
                   !address.Equals(IPAddress.IPv6None);
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] is not 0 and not 10 and not 127 &&
               !(bytes[0] == 100 && bytes[1] is >= 64 and <= 127) &&
               !(bytes[0] == 169 && bytes[1] == 254) &&
               !(bytes[0] == 172 && bytes[1] is >= 16 and <= 31) &&
               !(bytes[0] == 192 && bytes[1] == 168) &&
               !(bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2) &&
               !(bytes[0] == 198 && bytes[1] is 18 or 19) &&
               !(bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) &&
               !(bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) &&
               bytes[0] < 224;
    }

    private static string? GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool GetBoolean(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;

    private static double? GetDouble(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.TryGetDouble(out var number)
            ? number
            : null;

    private sealed record CacheEntry(GeoIpLocation Location, DateTimeOffset ExpiresAtUtc);
}
