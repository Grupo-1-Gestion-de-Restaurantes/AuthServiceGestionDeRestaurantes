using System.ComponentModel.DataAnnotations;

namespace AuthServiceGestionDeRestaurantes.Domain.Entities;
public class UserRole
{
    [Key]
    [MaxLength(16)]
    public string Id { get; set; } = string.Empty;

    [Required]
    [MaxLength(16)]
    public string UserId { get; set; } = string.Empty;

    [Required]
    [MaxLength(16)]
    public string RoleId { get; set; } = string.Empty;

    [Required]
    public User User { get; set; } = null!;

    [Required]
    public Role Role { get; set; } = null!;

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

}