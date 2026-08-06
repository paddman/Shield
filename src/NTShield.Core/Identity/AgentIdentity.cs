using System.Security.Cryptography;
using System.Text;
using NTShield.Core.Configuration;

namespace NTShield.Core.Identity;

public static class AgentIdentity
{
    public static string EnsureAgentId(AgentOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.AgentId))
        {
            return options.AgentId.Trim();
        }

        // Stable ID derived from machine name (no new GUIDs on every start).
        var material = $"{options.ComputerName}|{Environment.MachineName}|{Environment.UserDomainName}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        options.AgentId = Convert.ToHexString(hash.AsSpan(0, 8)).ToLowerInvariant();
        return options.AgentId;
    }
}
