using System.ComponentModel.DataAnnotations;

namespace AuthServiceGestionDeRestaurantes.Domain.Entities;
public class UserPasswordReset
{
    [Key]
    [MaxLength(16)]
    public string Id { get; set; } = string.Empty;

    [Required]
    [MaxLength(16)]
    public string UserId { get; set; } = string.Empty;

    [MaxLength(256)]
    public string? PasswordResetToken { get; set; }

    public DateTime? PasswordResetTokenExpiry { get; set; }

    [Required]
    public User User { get; set; } = null!;
}