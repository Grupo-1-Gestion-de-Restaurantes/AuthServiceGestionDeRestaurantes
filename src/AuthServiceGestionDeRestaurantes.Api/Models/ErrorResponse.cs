using System.Diagnostics;

namespace AuthServiceGestionDeRestaurantes.Api.Models;

public class ErrorResponse
{
    public int StatusCode { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public string? ErrorCode { get; set; }
    public string TraceId { get; set; } = Activity.Current?.Id ?? string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}