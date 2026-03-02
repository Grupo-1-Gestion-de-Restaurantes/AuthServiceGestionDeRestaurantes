using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace AuthServiceGestionDeRestaurantes.Application.DTOs;

public class LoginDto
{
    [Required]
    [DefaultValue("admin1")]
    public string EmailOrUsername { get; set; } = string.Empty;

    [Required]
    [DefaultValue("ADMIN123")]
    public string Password { get; set; } = string.Empty;
}