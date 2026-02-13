using Microsoft.AspNetCore.Mvc;

namespace AuthServiceGestionDeRestaurantes.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class HealthController : ControllerBase
{
    [HttpGet]
    public IActionResult GetHealth()
    {
        var response = new
        {
            status = "Healthy",
            timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            service = "GestionDeRestaurantes Authentication Service"
        };

        return Ok(response);
    }
}
