using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Duende.IdentityModel;
using IdentityServer8.Extensions;
using IdentityServerHost;
using IdentityServerHost.Configuration;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using IdentityServerHost.Extensions;
using Resources = IdentityServerHost.Configuration.Resources;
using Host.Configuration;
using Host.Extensions;

IdentityModelEventSource.ShowPII = true;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog();

var services = builder.Services;
var configuration = builder.Configuration;

// MVC / Razor Pages
services.AddControllersWithViews();

// Cookie policy (SameSite compatibility)
services.AddSameSiteCookiePolicy();

// IdentityServer
var identityServerBuilder =
    services.AddIdentityServer(options =>
    {
        options.Events.RaiseSuccessEvents = true;
        options.Events.RaiseFailureEvents = true;
        options.Events.RaiseErrorEvents = true;
        options.Events.RaiseInformationEvents = true;

        options.EmitScopesAsSpaceDelimitedStringInJwt = true;

        options.MutualTls.Enabled = true;
        options.MutualTls.DomainName = "mtls";
    })
    .AddInMemoryClients(Clients.Get())
    .AddInMemoryIdentityResources(Resources.IdentityResources)
    .AddInMemoryApiScopes(Resources.ApiScopes)
    .AddInMemoryApiResources(Resources.ApiResources)
    .AddSigningCredential()
    .AddExtensionGrantValidator<IdentityServerHost.Extensions.ExtensionGrantValidator>()
    .AddExtensionGrantValidator<IdentityServerHost.Extensions.NoSubjectExtensionGrantValidator>()
    .AddJwtBearerClientAuthentication()
    .AddAppAuthRedirectUriValidator()
    .AddTestUsers(TestUsers.Users)
    .AddProfileService<HostProfileService>()
    .AddCustomTokenRequestValidator<ParameterizedScopeTokenRequestValidator>()
    .AddScopeParser<ParameterizedScopeParser>()
    .AddMutualTlsSecretValidators();

// External Identity Providers
services.AddExternalIdentityProviders();

// Client certificate auth
services.AddAuthentication()
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.RevocationMode = X509RevocationMode.NoCheck;
    });

// Certificate forwarding (nginx / reverse proxy)
services.AddCertificateForwardingForNginx();

// Local API auth
services.AddLocalApiAuthentication(principal =>
{
    principal.Identities.First()
        .AddClaim(new Claim("additional_claim", "additional_value"));

    return Task.FromResult(principal);
});

Log.Logger = new LoggerConfiguration()
           .MinimumLevel.Debug()
           .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
           .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
           .MinimumLevel.Override("System", LogEventLevel.Warning)
           .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
           .Enrich.FromLogContext()
           //.WriteTo.File(@"IdentityServer8_log.txt")
           // uncomment to write to Azure diagnostics stream
           //.WriteTo.File(
           //    @"D:\home\LogFiles\Application\identityserver.txt",
           //    fileSizeLimitBytes: 1_000_000,
           //    rollOnFileSizeLimit: true,
           //    shared: true,
           //    flushToDiskInterval: TimeSpan.FromSeconds(1))
           .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Code)
           .CreateLogger();

var app = builder.Build();

// Forwarded headers
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders =
        ForwardedHeaders.XForwardedFor |
        ForwardedHeaders.XForwardedProto
});

app.UseCertificateForwarding();
app.UseCookiePolicy();

app.UseSerilogRequestLogging();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseStaticFiles();

app.UseRouting();

app.UseIdentityServer();
app.UseAuthorization();

app.MapDefaultControllerRoute();

app.Run();