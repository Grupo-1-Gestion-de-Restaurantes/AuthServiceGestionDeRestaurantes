using AuthServiceGestionDeRestaurantes.Application.DTOs;
using AuthServiceGestionDeRestaurantes.Application.DTOs.Email;
using AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;


namespace AuthServiceGestionDeRestaurantes.Application.Interfaces;

public interface IAuthService
{
    Task<RegisterResponseDto> RegisterAsync(RegisterDto registerDto);
    Task<AuthResponseDto> LoginAsync(LoginDto loginDto);
    Task<EmailResponseDto> VerifyEmailAsync(VerifyEmailDto verifyEmailDto);
    Task<EmailResponseDto> ResendVerificationEmailAsync(ResendVerificationDto resendDto);
    Task<EmailResponseDto> ForgotPasswordAsync(ForgotPasswordDto forgotPasswordDto);
    Task<EmailResponseDto> ResetPasswordAsync(ResetPasswordDto resetPasswordDto);
    Task<UserResponseDto?> GetUserByIdAsync(string userId);

    Task<TwoFactorSetupDto> SetupTwoFactorAsync(string userId);
    Task<bool> EnableTwoFactorAsync(string userId, string code);
    Task<bool> DisableTwoFactorAsync(string userId, string code);
    Task<bool> VerifyTwoFactorCodeAsync(string userId, string code);
    Task<List<string>> GenerateTwoFactorRecoveryCodesAsync(string userId);
}