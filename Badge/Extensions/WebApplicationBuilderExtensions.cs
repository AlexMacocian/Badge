using Badge.Converters;
using Badge.Filters;
using Badge.Middleware;
using Badge.Models;
using Badge.Options;
using Badge.Services.Applications;
using Badge.Services.Certificates;
using Badge.Services.Database.Applications;
using Badge.Services.Database.Certificates;
using Badge.Services.Database.OAuth;
using Badge.Services.Database.Users;
using Badge.Services.JWT;
using Badge.Services.OAuth2;
using Badge.Services.OAuth2.Handlers;
using Badge.Services.Passwords;
using Badge.Services.Passwords.Versions;
using Badge.Services.Status;
using Badge.Services.Users;
using Microsoft.Extensions.Options;
using Net.Sdk.Web;
using Net.Sdk.Web.Middleware;
using Net.Sdk.Web.Options;
using Serilog;
using Serilog.Settings.Configuration;
using System.Core.Extensions;
using System.Data.SQLite;

namespace Badge.Extensions;

public static class WebApplicationBuilderExtensions
{
    public static WebApplicationBuilder WithCorrelation(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull()
            .WithCorrelationVector()
            .Services
            .Configure<CorrelationVectorOptions>(builder.Configuration.GetRequiredSection("CorrelationVector"));

        return builder;
    }

    public static WebApplicationBuilder WithAntiforgery(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull();
        builder.Services.AddAntiforgery();

        return builder;
    }

    public static WebApplicationBuilder WithApplicationServices(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull()
            .Services
                .Configure<ApplicationOptions>(builder.Configuration.GetRequiredSection("Applications"))
                .Configure<ApplicationDatabaseOptions>(builder.Configuration.GetRequiredSection($"Applications:ApplicationDatabase"))
                .Configure<ApplicationMembershipDatabaseOptions>(builder.Configuration.GetRequiredSection($"Applications:MembershipDatabase"))
                .Configure<ClientSecretDatabaseOptions>(builder.Configuration.GetRequiredSection($"Applications:ClientSecretDatabase"))
                .AddScoped<IApplicationDatabase, SQLiteApplicationDatabase>()
                .AddScoped<IClientSecretDatabase, SQLiteClientSecretDatabase>()
                .AddScoped<IApplicationMembershipDatabase, SQLiteApplicationMembershipDatabase>()
                .AddScoped<IApplicationService, ApplicationService>();

        return builder;
    }

    public static WebApplicationBuilder WithUserServices(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull();
        builder.Services
                        .Configure<UserDatabaseOptions>(builder.Configuration.GetRequiredSection("Users"))
                        .Configure<UserServiceOptions>(builder.Configuration.GetRequiredSection("Users"))
                        .AddScoped<AuthenticationMiddleware>()
                        .AddScoped<LoginAuthenticatedFilter>()
                        .AddScoped<AuthenticatedUserAccessor>()
                        .AddScoped(sp => sp.GetRequiredService<AuthenticatedUserAccessor>().AuthenticatedUser!)
                        .AddScoped<IUserService, UserService>()
                        .AddScoped<IUserDatabase, SQLiteUserDatabase>();

        return builder;
    }

    public static WebApplicationBuilder WithSQLiteDatabase(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull();

        builder.Services
            .Configure<SQLiteDatabaseOptions>(builder.Configuration.GetRequiredSection("SQLiteDatabase"))
            .AddScoped(sp =>
            {
                var options = sp.GetRequiredService<IOptions<SQLiteDatabaseOptions>>();
                return new SQLiteConnection(options.Value.ConnectionString);
            });

        return builder;
    }

    public static WebApplicationBuilder WithPasswordServices(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull();
        builder
            .Services
            .Configure<PasswordServiceOptions>(builder.Configuration.GetRequiredSection("PasswordService"))
            .AddScoped<IPasswordServiceHashingAlgorithm, Rfc2898V1HashingAlgorithm>()
            .AddScoped<IPasswordService, PasswordService>();

        return builder;
    }

    public static WebApplicationBuilder WithJWTServices(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull()
            .ConfigureExtended<JWTServiceOptions>()
            .Services.AddScoped<IJWTService, JWTService>();
        return builder;
    }

    public static WebApplicationBuilder WithCertificateServices(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull()
            .Services
                     .Configure<CertificateServiceOptions>(builder.Configuration.GetRequiredSection("Certificates"))
                     .Configure<CertificateDatabaseOptions>(builder.Configuration.GetRequiredSection("Certificates"))
                     .AddScoped<ICertificateDatabase, SQLiteCertificateDatabase>()
                     .AddScoped<ICertificateService, CertificateService>();
        return builder;
    }

    public static WebApplicationBuilder WithSerializationContext(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull().Services.ConfigureHttpJsonOptions(options =>
        {
            options.SerializerOptions.Converters.Add(new IdentifierConverter());
            options.SerializerOptions.TypeInfoResolver = SerializationContext.Default;
        });

        return builder;
    }

    public static WebApplicationBuilder WithStatus(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull()
            .Services
            .Configure<StatusOptions>(builder.Configuration.GetRequiredSection("Status"))
            .AddScoped<IStatusService, StatusService>();

        return builder;
    }

    public static WebApplicationBuilder WithAuthorize(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull()
            .Services
                .Configure<OAuthServiceOptions>(builder.Configuration.GetRequiredSection("OAuth"))
                .Configure<OAuthCodeOptions>(builder.Configuration.GetRequiredSection("OAuth:Code"))
                .Configure<OAuthRefreshTokenOptions>(builder.Configuration.GetRequiredSection("OAuth:RefreshToken"))
                .Configure<OAuthAccessTokenOptions>(builder.Configuration.GetRequiredSection("OAuth:AccessToken"))
                .Configure<OAuthOpenIdTokenOptions>(builder.Configuration.GetRequiredSection("OAuth:OpenIdToken"))
                .AddScoped<IOAuthCodeDatabase, SQLiteOAuthCodeDatabase>()
                .AddScoped<IOAuthRefreshTokenDatabase, SQLiteOAuthRefreshTokenDatabase>()
                .AddScoped<IOAuth2Service, OAuth2Service>()
                .AddScoped<IOAuthRequestHandler, OAuthCodeRequestHandler>()
                .AddScoped<IOAuthRequestHandler, OAuthAccessTokenRequestHandler>()
                .AddScoped<IOAuthRequestHandler, OAuthOpenIdTokenRequestHandler>()
                .AddScoped<IOAuthRequestHandler, OAuthRefreshTokenRequestHandler>();

        return builder;
    }

    public static WebApplicationBuilder WithHttpContextAccessor(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull().Services.AddHttpContextAccessor();
        return builder;
    }

    public static WebApplicationBuilder WithHealthChecks(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull().Services.AddHealthChecks();
        return builder;
    }

    public static WebApplicationBuilder WithFormattedLogging(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull()
            .Logging.ClearProviders()
            .AddSerilog(logger: new LoggerConfiguration()
                .ReadFrom.Configuration(builder.Configuration, new ConfigurationReaderOptions
                {
                    SectionName = "Logging"
                })
                .Enrich.FromLogContext()
                .WriteTo.Console(
                    outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss}] {Level:u4}: [{ClientIP}] [{CorrelationVector}] [{SourceContext}]{NewLine}{Message:lj}{NewLine}{Exception}",
                    theme: Serilog.Sinks.SystemConsole.Themes.SystemConsoleTheme.Colored)
                .CreateLogger());

        return builder;
    }

    public static WebApplicationBuilder WithLoggingEnrichment(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull()
            .Services.AddScoped<LoggingEnrichmentMiddleware>();

        return builder;
    }

    public static WebApplicationBuilder WithHeaderLoggingMiddleware(this WebApplicationBuilder builder)
    {
        builder.ThrowIfNull()
            .Services.AddScoped<HeaderLoggingMiddleware>();

        return builder;
    }
}
