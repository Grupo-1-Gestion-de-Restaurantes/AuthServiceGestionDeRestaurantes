namespace AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;

public class TwoFactorSetupDto
{
    public string SecretKey { get; set; } = string.Empty;
    public string QrCodeImage { get; set; } = string.Empty;
    public string ManualEntryKey { get; set; } = string.Empty;
    public List<string> RecoveryCodes { get; set; } = new();
}