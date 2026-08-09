namespace NTShield.Server.Security;

public sealed class DashboardAuthOptions
{
    public const string SectionName = "DashboardAuth";

    public string CookieName { get; set; } = "__Host-NTShield.Session";
    public int SessionHours { get; set; } = 8;
    public string? DataProtectionPath { get; set; }
    public bool LegacyKeyExchangeEnabled { get; set; } = true;
    public OidcDashboardAuthOptions Oidc { get; set; } = new();
    public LocalDashboardAuthOptions Local { get; set; } = new();
}

public sealed class OidcDashboardAuthOptions
{
    public bool Enabled { get; set; }
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string CallbackPath { get; set; } = "/signin-oidc";
    public string NameClaim { get; set; } = "name";
    public string RoleClaim { get; set; } = "roles";
    public string TenantClaim { get; set; } = "ntshield_tenants";
    /// <summary>
    /// Explicit fallback tenant grants for identity providers that cannot emit
    /// the configured tenant claim. Empty means the user receives no tenant
    /// access; it never silently expands to all tenants.
    /// </summary>
    public List<string> DefaultTenantIds { get; set; } = [];
    public string DefaultRole { get; set; } = DashboardRoles.Executive;
    public bool RequireHttpsMetadata { get; set; } = true;
}

public sealed class LocalDashboardAuthOptions
{
    public bool Enabled { get; set; }
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = "Break-glass administrator";

    /// <summary>
    /// PBKDF2-SHA256 encoded as pbkdf2-sha256$iterations$saltBase64$hashBase64.
    /// Plaintext passwords are never accepted from configuration.
    /// </summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>RFC 6238 Base32 secret. A local account is unusable without MFA.</summary>
    public string TotpSecret { get; set; } = string.Empty;
    public List<string> TenantIds { get; set; } = ["*"];
}

public static class DashboardRoles
{
    public const string SocAdmin = "SocAdmin";
    public const string SocOperator = "SocOperator";
    public const string Executive = "Executive";

    public static bool IsKnown(string? role) =>
        string.Equals(role, SocAdmin, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(role, SocOperator, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(role, Executive, StringComparison.OrdinalIgnoreCase);
}

public static class DashboardCapabilities
{
    public const string DashboardView = "dashboard:view";
    public const string ThreatsView = "threats:view";
    public const string IncidentsManage = "incidents:manage";
    public const string PacketView = "packets:view";
    public const string PacketExport = "packets:export";
    public const string CaptureAdmin = "capture:admin";
    public const string TenantAdmin = "tenant:admin";

    public static IReadOnlyList<string> ForRoles(IEnumerable<string> roles)
    {
        var normalized = new HashSet<string>(
            roles.Where(DashboardRoles.IsKnown),
            StringComparer.OrdinalIgnoreCase);
        if (normalized.Count == 0) return Array.Empty<string>();

        var capabilities = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { DashboardView };

        if (normalized.Contains(DashboardRoles.SocOperator) || normalized.Contains(DashboardRoles.SocAdmin))
        {
            capabilities.Add(ThreatsView);
            capabilities.Add(IncidentsManage);
            capabilities.Add(PacketView);
            capabilities.Add(PacketExport);
        }

        if (normalized.Contains(DashboardRoles.SocAdmin))
        {
            capabilities.Add(CaptureAdmin);
            capabilities.Add(TenantAdmin);
        }

        return capabilities.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
