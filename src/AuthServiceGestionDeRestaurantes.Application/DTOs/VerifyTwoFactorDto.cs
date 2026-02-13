using System.ComponentModel.DataAnnotations;

namespace AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;

public class VerifyTwoFactorDto
{
    [Required]
    public string Code { get; set; } = string.Empty;
}