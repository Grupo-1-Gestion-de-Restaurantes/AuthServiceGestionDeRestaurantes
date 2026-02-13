using System.ComponentModel.DataAnnotations;

namespace AuthServiceGestionDeRestaurantes.Domain.Entities;

public class TwoFactorAuth
{
    [Key]
    [MaxLength(16)]
    public string Id { get; set; } = string.Empty;

    [Required]
    [MaxLength(16)]
    public string UserId { get; set; } = string.Empty;

    [Required]
    public string SecretKey { get; set; } = string.Empty;

    public bool IsEnabled { get; set; } = false;

    public DateTime? EnabledAt { get; set; }

    public List<string> RecoveryCodes { get; set; } = new();

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public virtual User User { get; set; } = null!;
}