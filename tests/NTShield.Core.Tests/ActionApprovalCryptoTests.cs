using System.Security.Cryptography;
using NTShield.Shared.Models;
using NTShield.Shared.Security;
using Xunit;

namespace NTShield.Core.Tests;

public sealed class ActionApprovalCryptoTests
{
    [Fact]
    public void Signed_TargetBound_Action_Is_Approved()
    {
        var keys = CreateKeys();
        ActionApprovalCrypto.ConfigureSigningKey(keys.PrivatePem, keys.PublicPem, keys.KeyId);
        var request = NewDestructiveRequest();

        ActionApprovalCrypto.Sign(
            request,
            approvedBy: "operator",
            lifetime: TimeSpan.FromMinutes(5));

        Assert.True(request.ApprovalRequested);
        Assert.True(request.Approved);
        Assert.Equal(keys.KeyId, request.ApprovalKeyId);
        Assert.NotNull(request.PayloadSha256);
        Assert.NotNull(request.ApprovalSignature);
    }

    [Fact]
    public void Tampering_With_Target_Invalidates_Approval()
    {
        var keys = CreateKeys();
        ActionApprovalCrypto.ConfigureSigningKey(keys.PrivatePem, keys.PublicPem, keys.KeyId);
        var request = NewDestructiveRequest();
        ActionApprovalCrypto.Sign(request, "operator", TimeSpan.FromMinutes(5));
        Assert.True(request.Approved);

        request.TargetIp = "10.0.0.99";

        Assert.False(request.Approved);
    }

    [Fact]
    public void Expired_Action_Is_Not_Approved()
    {
        var keys = CreateKeys();
        ActionApprovalCrypto.ConfigureSigningKey(keys.PrivatePem, keys.PublicPem, keys.KeyId);
        var request = NewDestructiveRequest();
        ActionApprovalCrypto.Sign(
            request,
            "operator",
            TimeSpan.FromMinutes(1),
            DateTimeOffset.UtcNow.AddMinutes(-10));

        Assert.True(request.ApprovalRequested);
        Assert.False(request.Approved);
    }

    [Fact]
    public void Boolean_Approved_Without_Signature_Fails_Closed()
    {
        var keys = CreateKeys();
        ActionApprovalCrypto.ConfigureTrustedPublicKey(keys.PublicPem, keys.KeyId);
        var request = NewDestructiveRequest();

        request.Approved = true;
        request.ApprovalId = "client-claimed-approval";
        request.ApprovedBy = "operator";
        request.ApprovedAtUtc = DateTimeOffset.UtcNow;
        request.ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5);
        request.Nonce = new string('a', 48);
        request.ApprovalKeyId = keys.KeyId;
        request.PayloadSha256 = ActionApprovalCrypto.ComputePayloadSha256(request);

        Assert.True(request.ApprovalRequested);
        Assert.False(request.Approved);
    }

    private static ResponseActionRequest NewDestructiveRequest() => new()
    {
        RequestId = Guid.NewGuid().ToString("N"),
        Requester = "operator",
        TargetAgentId = "agent-001",
        ActionType = "BlockSourceIp",
        Reason = "confirmed password spray",
        TargetIp = "10.0.0.8",
        Direction = "in",
        Protocol = "tcp",
        Approved = true,
        DurationMinutes = 5
    };

    private static (string PrivatePem, string PublicPem, string KeyId) CreateKeys()
    {
        using var rsa = RSA.Create(2048);
        var privatePem = rsa.ExportPkcs8PrivateKeyPem();
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();
        return (privatePem, publicPem, ActionApprovalCrypto.ComputeKeyId(publicPem));
    }
}
