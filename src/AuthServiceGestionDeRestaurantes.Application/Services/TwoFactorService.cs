using System.Security.Cryptography;
using AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;
using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using AuthServiceGestionDeRestaurantes.Domain.Entities;
using AuthServiceGestionDeRestaurantes.Domain.Interfaces;
using Microsoft.Extensions.Logging;
using OtpNet;
using QRCoder;

namespace AuthServiceGestionDeRestaurantes.Application.Services;

public class TwoFactorService : ITwoFactorService
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<TwoFactorService> _logger;

    public TwoFactorService(IUserRepository userRepository, ILogger<TwoFactorService> logger)
    {
        _userRepository = userRepository;
        _logger = logger;
    }

public async Task<TwoFactorSetupDto> GenerateSetupAsync(string userId)
{
    _logger.LogInformation("Iniciando GenerateSetupAsync para usuario {UserId}", userId);
    
    var user = await _userRepository.GetByIdAsync(userId);
    _logger.LogInformation("Usuario obtenido: {Email}, TwoFactorAuth existe: {Exists}", 
        user.Email, user.TwoFactorAuth != null);
    
    if (user.TwoFactorAuth != null)
    {
        _logger.LogInformation("Eliminando TwoFactorAuth existente con ID: {Id}", user.TwoFactorAuth.Id);
        await _userRepository.DeleteTwoFactorAuthAsync(user.TwoFactorAuth.Id);
        _logger.LogInformation("TwoFactorAuth eliminado de la BD");
        
        user = await _userRepository.GetByIdAsync(userId);
        _logger.LogInformation("Usuario recargado, TwoFactorAuth ahora es null: {IsNull}", user.TwoFactorAuth == null);
    }
    else
    {
        _logger.LogInformation("No existía TwoFactorAuth previo para el usuario");
    }
    
    var secretKey = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
    _logger.LogDebug("SecretKey generada");
    
    var issuer = "GestionRestaurantes";
    var account = $"{user.Email}";
    var uri = new OtpUri(OtpType.Totp, secretKey, account, issuer);
    
    using var qrGenerator = new QRCodeGenerator();
    using var qrCodeData = qrGenerator.CreateQrCode(uri.ToString(), QRCodeGenerator.ECCLevel.Q);
    using var qrCode = new PngByteQRCode(qrCodeData);
    var qrCodeBytes = qrCode.GetGraphic(20);
    var qrCodeBase64 = Convert.ToBase64String(qrCodeBytes);
    _logger.LogDebug("QR Code generado");
    
    var recoveryCodes = GenerateRecoveryCodes(8);
    _logger.LogDebug("{Count} códigos de recuperación generados", recoveryCodes.Count);
    
    var twoFactorAuth = new TwoFactorAuth
    {
        Id = UuidGenerator.GenerateUserId(),
        UserId = userId,
        SecretKey = secretKey,
        IsEnabled = false,
        RecoveryCodes = recoveryCodes,
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow
    };
    
    // 🔥 NUEVO: Guardar directamente, sin tocar user.TwoFactorAuth
    _logger.LogInformation("Guardando TwoFactorAuth directamente en la base de datos");
    await _userRepository.AddTwoFactorAuthAsync(twoFactorAuth);
    _logger.LogInformation("TwoFactorAuth guardado correctamente con ID: {Id}", twoFactorAuth.Id);
    
    return new TwoFactorSetupDto
    {
        SecretKey = secretKey,
        QrCodeImage = $"data:image/png;base64,{qrCodeBase64}",
        ManualEntryKey = secretKey,
        RecoveryCodes = recoveryCodes
    };
}

    public async Task<bool> VerifyAndEnableAsync(string userId, string code)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user?.TwoFactorAuth == null)
            return false;
            
        if (!VerifyTotp(user.TwoFactorAuth.SecretKey, code))
            return false;
            
        user.TwoFactorAuth.IsEnabled = true;
        user.TwoFactorAuth.EnabledAt = DateTime.UtcNow;
        user.TwoFactorAuth.UpdatedAt = DateTime.UtcNow;
        
        await _userRepository.UpdateAsync(user);
        
        _logger.LogInformation("2FA enabled for user {UserId}", userId);
        return true;
    }

    public async Task<bool> VerifyCodeAsync(string userId, string code)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user?.TwoFactorAuth == null || !user.TwoFactorAuth.IsEnabled)
            return false;
            
        return VerifyTotp(user.TwoFactorAuth.SecretKey, code);
    }

    public async Task<bool> DisableAsync(string userId, string code)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user?.TwoFactorAuth == null || !user.TwoFactorAuth.IsEnabled)
            return false;
            
        if (!VerifyTotp(user.TwoFactorAuth.SecretKey, code))
            return false;
            
        user.TwoFactorAuth.IsEnabled = false;
        user.TwoFactorAuth.EnabledAt = null;
        user.TwoFactorAuth.UpdatedAt = DateTime.UtcNow;
        
        await _userRepository.UpdateAsync(user);
        
        _logger.LogInformation("2FA disabled for user {UserId}", userId);
        return true;
    }

    public async Task<List<string>> GenerateRecoveryCodesAsync(string userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user?.TwoFactorAuth == null)
            return new List<string>();
            
        var codes = GenerateRecoveryCodes(8);
        user.TwoFactorAuth.RecoveryCodes = codes;
        user.TwoFactorAuth.UpdatedAt = DateTime.UtcNow;
        
        await _userRepository.UpdateAsync(user);
        return codes;
    }

    private static bool VerifyTotp(string secretKey, string code)
    {
        try
        {
            var secretBytes = Base32Encoding.ToBytes(secretKey);
            var totp = new Totp(secretBytes, step: 30, totpSize: 6);
            return totp.VerifyTotp(code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);
        }
        catch
        {
            return false;
        }
    }

    private static List<string> GenerateRecoveryCodes(int count)
    {
        var codes = new List<string>();
        using var rng = RandomNumberGenerator.Create();
        
        for (int i = 0; i < count; i++)
        {
            var bytes = new byte[6];
            rng.GetBytes(bytes);
            var code = Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "")
                .Substring(0, 8)
                .ToUpperInvariant();
                
            codes.Add(code);
        }
        
        return codes;
    }
}