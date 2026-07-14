using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using AuthServiceGestionDeRestaurantes.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
namespace AuthServiceGestionDeRestaurantes.Application.Services;

public class JwtTokenService(IConfiguration configuration) : IJwtTokenService
{
    public string GenerateToken(User user)
    {
        var jwtSettings = configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");
        var issuer = jwtSettings["Issuer"] ?? "AuthDotnet";
        var audience = jwtSettings["Audience"] ?? "AuthDotnet";
        var expiryInMinutes = int.Parse(jwtSettings["ExpiryInMinutes"] ?? "30");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Get user's role (assumes single role per user)
        var role = user.UserRoles?.FirstOrDefault()?.Role?.Name ?? "USER_ROLE";

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new Claim("role", role),
            new Claim("name", $"{user.Name} {user.Surname}"),
            new Claim("email", user.Email),
            new Claim("phone", user.UserProfile?.Phone ?? string.Empty)
        };

        // Admins y managers solo cierran sesión manualmente (logout), no por expiración del token.
        var isStaffRole = role is "ADMIN_ROLE" or "MANAGER_ROLE";
        var expires = isStaffRole
            ? DateTime.UtcNow.AddYears(10)
            : DateTime.UtcNow.AddMinutes(expiryInMinutes);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: expires,
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
