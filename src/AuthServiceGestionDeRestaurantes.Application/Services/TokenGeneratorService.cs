using System.Security.Cryptography;

namespace AuthServiceGestionDeRestaurantes.Application.Services;

public static class TokenGeneratorService
{
    public static string GenerateEmailVerificationToken()
    {
        return GenerateSecureToken(32);
    }

    public static string GeneratePasswordResetToken()
    {
        return GenerateSecureToken(32);
    }

    private static string GenerateSecureToken(int length)
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[length];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
}