using AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;

namespace AuthServiceGestionDeRestaurantes.Application.Interfaces;

public interface ITwoFactorService
{
    Task<TwoFactorSetupDto> GenerateSetupAsync(string userId);
    Task<bool> VerifyAndEnableAsync(string userId, string code);
    Task<bool> VerifyCodeAsync(string userId, string code);
    Task<bool> DisableAsync(string userId, string code);
    Task<List<string>> GenerateRecoveryCodesAsync(string userId);
}