using NTShield.Server.Signatures;
using NTShield.Server.Syslog;
using NTShield.Shared.Enums;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class SyslogAlertTests
{
    [Fact]
    public void Forwarded_Agent_Alert_Uses_Original_Detection_Details()
    {
        var hit = new SignatureHit
        {
            Signature = new SignatureDefinition
            {
                Id = "OS-NTSHIELD-ALERT",
                Name = "NT Shield agent alert (syslog forward)",
                Severity = "High"
            },
            Message = new ParsedSyslogMessage
            {
                Host = "WIN-2IMDRHSSMTJ",
                SourceIp = "203.113.71.200",
                Message = "NTShield-ALERT RuleId=DET-POWERSHELL Severity=Critical Title=Suspicious PowerShell usage SourceIp=203.113.71.200 DestIp=- User=admin Host=WIN-2IMDRHSSMTJ AlertId=abc123 Desc=Encoded PowerShell command detected"
            }
        };

        var alert = OpenSourceSignatureEngine.ToAlert(hit);

        Assert.Equal("DET-POWERSHELL", alert.RuleId);
        Assert.Equal("Suspicious PowerShell usage", alert.Title);
        Assert.Equal(Severity.Critical, alert.Severity);
        Assert.Equal("Encoded PowerShell command detected", alert.Description);
        Assert.Equal("203.113.71.200", alert.SourceIp);
        Assert.Equal("admin", alert.Username);
    }
}
