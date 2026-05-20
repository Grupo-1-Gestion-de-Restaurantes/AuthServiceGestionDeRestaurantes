using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using System.ComponentModel.DataAnnotations;

namespace AuthServiceGestionDeRestaurantes.Application.DTOs;

public class UpdateProfileDto
{
    [Required(ErrorMessage = "El nombre es obligatorio.")]
    [MaxLength(25, ErrorMessage = "El nombre no puede tener más de 25 caracteres.")]
    public string Name { get; set; } = string.Empty;

    [Required(ErrorMessage = "El apellido es obligatorio.")]
    [MaxLength(25, ErrorMessage = "El apellido no puede tener más de 25 caracteres.")]
    public string Surname { get; set; } = string.Empty;

    [Required(ErrorMessage = "El número de teléfono es obligatorio")]
    [StringLength(8, MinimumLength = 8, ErrorMessage = "El número de teléfono debe tener exactamente 8 dígitos")]
    [RegularExpression(@"^\d{8}$", ErrorMessage = "El teléfono solo debe contener números")]
    public string Phone { get; set; } = string.Empty;

    public IFileData? ProfilePicture { get; set; }
}
