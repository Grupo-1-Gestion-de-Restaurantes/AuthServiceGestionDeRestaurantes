using System.ComponentModel.DataAnnotations;

namespace AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;

public class DisableTwoFactorDto
{
    [Required]
    public string Code { get; set; } = string.Empty;
}