namespace AuthServiceGestionDeRestaurantes.Application.DTOs.Email;

public class EmailResponseDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public object? Data { get; set; }
}