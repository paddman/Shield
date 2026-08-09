using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.DataProtection;

namespace NTShield.Server.Capture;

public static class CaptureServiceCollectionExtensions
{
    public const string ProviderClientName = "capture-provider";

    public static IServiceCollection AddCaptureControlPlane(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddDataProtection();
        services.AddOptions<CaptureControlOptions>()
            .Bind(configuration.GetSection(CaptureControlOptions.SectionName))
            .Validate(ValidateOptions, "CaptureControl configuration is invalid.")
            .ValidateOnStart();
        services.AddHttpClient(ProviderClientName, client =>
        {
            client.Timeout = Timeout.InfiniteTimeSpan;
            client.DefaultRequestHeaders.UserAgent.ParseAdd("NTShield-Capture-Control/1.0");
        });
        services.AddSingleton<ICaptureControlStore, SqliteCaptureControlStore>();
        services.AddSingleton<CaptureProviderRegistry>();
        services.AddSingleton<ICaptureProviderResolver>(provider => provider.GetRequiredService<CaptureProviderRegistry>());
        services.AddSingleton<CaptureCapacityService>();
        services.AddSingleton<CapturePolicyService>();
        services.AddSingleton<CaptureSessionService>();
        services.AddSingleton<CaptureHealthService>();
        services.AddSingleton<CaptureEnabledEndpointFilter>();
        services.AddSingleton<CaptureExceptionEndpointFilter>();
        services.AddHostedService<CaptureControlInitializer>();
        services.AddHostedService<CaptureProviderHealthWorker>();
        services.AddHostedService<CaptureProviderSyncWorker>();
        services.AddHostedService<CapturePolicyReconcileWorker>();
        services.AddHostedService<CaptureExportWorker>();
        services.AddHostedService<CaptureRetentionWorker>();
        return services;
    }

    private static bool ValidateOptions(CaptureControlOptions options)
    {
        if (!options.Enabled) return true;
        if (!string.Equals(options.StoreKind, "sqlite-lab", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(options.DatabasePath) ||
            options.MaxPoliciesPerTenant is < 1 or > 1000 ||
            options.MaxSessionsPerQuery is < 1 or > 1000 ||
            options.MaxExportSessions is < 1 or > 500 ||
            options.MaxTlsPreviewTransactions is < 1 or > 100 ||
            options.DefaultSessionRetentionDays is < 1 or > 90 ||
            options.MaxSessionMetadataRetentionDays is < 1 or > 90 ||
            options.DefaultSessionRetentionDays > options.MaxSessionMetadataRetentionDays ||
            options.MaxProviderResponseBytes is < 65_536 or > 64 * 1024 * 1024 ||
            options.ExportClaimLeaseSeconds is < 30 or > 900 ||
            options.PolicyDispatchLeaseSeconds is < 30 or > 900 ||
            options.ProviderMutationLeaseSeconds is < 5 or > 120 ||
            options.ProviderMutationLockWaitSeconds is < 1 or > 60 ||
            options.DefaultTenantCapacityBytes <= 0 ||
            options.CapacityAdmissionPercent is <= 0m or > 100m)
            return false;
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var provider in options.Providers.Where(item => item.Enabled))
        {
            if (string.IsNullOrWhiteSpace(provider.Id) || !ids.Add(provider.Id) ||
                string.IsNullOrWhiteSpace(provider.BaseUrl) || !provider.FailOpen ||
                string.IsNullOrWhiteSpace(provider.ApiKey) || provider.ApiKey.Length > 4096 ||
                provider.ApiKey.Any(char.IsControl) ||
                provider.TenantIds is null || provider.TenantIds.Count == 0 ||
                provider.TenantIds.Distinct(StringComparer.OrdinalIgnoreCase).Count() != provider.TenantIds.Count ||
                provider.TenantIds.Any(tenant => !System.Text.RegularExpressions.Regex.IsMatch(
                    tenant, "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")) ||
                provider.Capabilities is null || provider.Capabilities.Count > 20 ||
                provider.Capabilities.Any(capability =>
                    string.IsNullOrWhiteSpace(capability) || capability.Length > 64 ||
                    !System.Text.RegularExpressions.Regex.IsMatch(capability, "^[A-Za-z0-9][A-Za-z0-9._:-]*$")) ||
                new[] { provider.HealthPath, provider.SessionsPath, provider.PolicyPath, provider.AccessPath,
                        provider.RevokeAccessPath, provider.TlsPreviewPath,
                        provider.ExportPath, provider.DeletePayloadPath }.Any(path =>
                    string.IsNullOrWhiteSpace(path) || !path.StartsWith('/') || path.StartsWith("//")))
                return false;
        }
        return options.Providers.Any(item => item.Enabled);
    }
}
