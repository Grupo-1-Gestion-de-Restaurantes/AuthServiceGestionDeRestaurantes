using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using AuthServiceGestionDeRestaurantes.Application.Services;
using AuthServiceGestionDeRestaurantes.Domain.Interfaces;
using AuthServiceGestionDeRestaurantes.Persistence.Data;
using AuthServiceGestionDeRestaurantes.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Resend;

namespace AuthServiceGestionDeRestaurantes.Api.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Connection string 'DefaultConnection' is missing or empty. " +
                "In Docker set ConnectionStrings__DefaultConnection " +
                "(e.g. Host=postgres;Port=5432;Database=...;Username=...;Password=...).");
        }

        var dataSourceBuilder = new NpgsqlDataSourceBuilder(connectionString);
        dataSourceBuilder.EnableDynamicJson();
        var dataSource = dataSourceBuilder.Build();

        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseNpgsql(dataSource)
                .UseSnakeCaseNamingConvention());

        // Resend email client (API key via config or RESEND_API_KEY env var — never hardcode secrets)
        services.AddOptions();
        services.AddResend(o =>
        {
            var apiKey = configuration["ResendSettings:ApiKey"];
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                apiKey = Environment.GetEnvironmentVariable("RESEND_API_KEY");
            }

            o.ApiToken = apiKey ?? string.Empty;
            o.ThrowExceptions = false;
        }).ConfigureHttpClient(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
        });

        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IUserManagementService, UserManagementService>();
        services.AddScoped<IPasswordHashService, PasswordHashService>();
        services.AddScoped<IJwtTokenService, JwtTokenService>();
        services.AddScoped<ICloudinaryService, CloudinaryService>();
        services.AddScoped<IEmailService, EmailService>();
        services.AddScoped<ITwoFactorService, TwoFactorService>();

        services.AddHealthChecks();

        return services;
    }

    public static IServiceCollection AddApiDocumentation(this IServiceCollection services)
    {
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen();

        return services;
    }
}