using System.Reflection;

namespace NTShield.Shared;

/// <summary>Product version helpers — shown in Dashboard, Tray, Agent status, Central health.</summary>
public static class ProductInfo
{
    public const string ProductName = "NT Shield";

    /// <summary>Semantic version of the calling entry assembly (e.g. 1.0.11).</summary>
    public static string GetVersion(Assembly? assembly = null)
    {
        assembly ??= Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
        var info = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(info))
        {
            // Strip git hash suffix from SourceLink: 1.0.11+abc123
            var plus = info.IndexOf('+', StringComparison.Ordinal);
            return plus > 0 ? info[..plus] : info;
        }

        var v = assembly.GetName().Version;
        if (v is null) return "0.0.0";
        return v.Revision > 0 ? v.ToString(4) : v.ToString(3);
    }

    public static string Format(string component, Assembly? assembly = null) =>
        $"{component} v{GetVersion(assembly)}";
}
