using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NTShield.Server.Security;
using Xunit;

namespace NTShield.Integration.Tests;

public sealed class DashboardSecurityTests
{
    [Fact]
    public void Local_BreakGlass_Requires_Pbkdf2_Password_And_Totp()
    {
        var salt = Enumerable.Range(1, 16).Select(value => (byte)value).ToArray();
        const int iterations = 210_000;
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            "correct horse battery staple",
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            32);
        var encoded = $"pbkdf2-sha256${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        var validator = new LocalDashboardCredentialValidator(Options.Create(new DashboardAuthOptions
        {
            Local = new LocalDashboardAuthOptions
            {
                Enabled = true,
                Username = "soc-admin",
                PasswordHash = encoded,
                TotpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
            }
        }));

        var time = DateTimeOffset.FromUnixTimeSeconds(59);
        Assert.True(validator.Validate("soc-admin", "correct horse battery staple", "287082", time));
        Assert.False(validator.Validate("soc-admin", "wrong", "287082", time));
        Assert.False(validator.Validate("soc-admin", "correct horse battery staple", "000000", time));
        Assert.False(validator.Validate("SOC-ADMIN", "correct horse battery staple", "287082", time));
    }

    [Fact]
    public void Weak_Or_Malformed_Password_Hashes_Are_Rejected()
    {
        Assert.False(LocalDashboardCredentialValidator.VerifyPassword("secret", "secret"));
        Assert.False(LocalDashboardCredentialValidator.VerifyPassword(
            "secret",
            "pbkdf2-sha256$1000$YWJj$YWJj"));
        Assert.False(LocalDashboardCredentialValidator.VerifyTotp("not-base32!", "123456", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Capability_Mapping_Does_Not_Grant_Packet_Access_To_Executives()
    {
        var executive = DashboardCapabilities.ForRoles([DashboardRoles.Executive]);
        Assert.Contains(DashboardCapabilities.DashboardView, executive);
        Assert.DoesNotContain(DashboardCapabilities.PacketView, executive);

        var soc = DashboardCapabilities.ForRoles([DashboardRoles.SocOperator]);
        Assert.Contains(DashboardCapabilities.PacketView, soc);
        Assert.Contains(DashboardCapabilities.PacketExport, soc);
        Assert.DoesNotContain(DashboardCapabilities.CaptureAdmin, soc);

        var admin = DashboardCapabilities.ForRoles([DashboardRoles.SocAdmin]);
        Assert.Contains(DashboardCapabilities.CaptureAdmin, admin);
    }

    [Fact]
    public void Oidc_Session_Without_Tenant_Claim_Does_Not_Gain_Wildcard_Access()
    {
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "alice"),
                new Claim(ClaimTypes.Role, DashboardRoles.Executive)
            ], DashboardSessionEndpoints.CookieScheme))
        };

        var response = DashboardSessionEndpoints.BuildSessionResponse(
            context,
            new SecurityOptions { RequireAuth = true },
            new DashboardAuthOptions(),
            "test",
            new string('a', 64));
        var tenantIds = response.GetType().GetProperty("tenantIds")?.GetValue(response) as string[];
        var roles = response.GetType().GetProperty("roles")?.GetValue(response) as string[];
        var capabilities = response.GetType().GetProperty("capabilities")?.GetValue(response) as IReadOnlyList<string>;

        Assert.NotNull(tenantIds);
        Assert.Empty(tenantIds!);
        Assert.NotNull(roles);
        Assert.Contains(DashboardRoles.Executive, roles!);
        Assert.NotNull(capabilities);
        Assert.Contains(DashboardCapabilities.DashboardView, capabilities!);
    }

    [Fact]
    public void Authenticated_Session_Without_Known_Role_Does_Not_Advertise_Dashboard_Access()
    {
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "roleless-user")
            ], DashboardSessionEndpoints.CookieScheme))
        };

        var response = DashboardSessionEndpoints.BuildSessionResponse(
            context,
            new SecurityOptions { RequireAuth = true },
            new DashboardAuthOptions(),
            "test",
            new string('a', 64));
        var roles = response.GetType().GetProperty("roles")?.GetValue(response) as string[];
        var capabilities = response.GetType().GetProperty("capabilities")?.GetValue(response) as IReadOnlyList<string>;

        Assert.NotNull(roles);
        Assert.Empty(roles!);
        Assert.NotNull(capabilities);
        Assert.DoesNotContain(DashboardCapabilities.DashboardView, capabilities!);
    }

    [Fact]
    public async Task Cookie_Authenticated_Mutation_Requires_Matching_Csrf_Header()
    {
        var reached = false;
        var middleware = new DashboardCsrfMiddleware(_ =>
        {
            reached = true;
            return Task.CompletedTask;
        });
        var denied = AuthenticatedPostContext();
        await middleware.InvokeAsync(denied);
        Assert.Equal(StatusCodes.Status403Forbidden, denied.Response.StatusCode);
        Assert.False(reached);

        var accepted = AuthenticatedPostContext();
        accepted.Request.Headers.Cookie = $"{DashboardSessionEndpoints.CsrfCookie}={new string('b', 64)}";
        accepted.Request.Headers[DashboardSessionEndpoints.CsrfHeader] = new string('b', 64);
        await middleware.InvokeAsync(accepted);
        Assert.True(reached);
    }

    private static DefaultHttpContext AuthenticatedPostContext()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/api/v2/capture-policies";
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "soc-user"),
            new Claim(ClaimTypes.Role, DashboardRoles.SocAdmin)
        ], DashboardSessionEndpoints.CookieScheme));
        context.Response.Body = new MemoryStream();
        return context;
    }
}
