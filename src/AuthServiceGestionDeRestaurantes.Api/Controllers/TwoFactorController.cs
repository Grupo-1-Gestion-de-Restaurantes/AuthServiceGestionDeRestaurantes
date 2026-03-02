using AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;
using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace AuthServiceGestionDeRestaurantes.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
[Authorize]
[SwaggerTag("Endpoints para gestionar la autenticación de dos factores (2FA)")]
public class TwoFactorController : ControllerBase
{
    private readonly IAuthService _authService;

    public TwoFactorController(IAuthService authService)
    {
        _authService = authService;
    }
    private string GetUserId()
    {
        var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == "sub" ||
            c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");

        if (userIdClaim == null || string.IsNullOrEmpty(userIdClaim.Value))
            throw new UnauthorizedAccessException();

        return userIdClaim.Value;
    }

    [HttpPost("setup")]
    [SwaggerOperation(
        Summary = "Configura el 2FA",
        Description = "Genera la llave secreta y la URI para el código QR que se escaneará con Google Authenticator o Authy."
    )]
    [ProducesResponseType(typeof(TwoFactorSetupDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<TwoFactorSetupDto>> Setup()
    {
        var userId = GetUserId();
        var result = await _authService.SetupTwoFactorAsync(userId);
        return Ok(result);
    }

    [HttpPost("verify-and-enable")]
    [SwaggerOperation(
        Summary = "Verifica y activa el 2FA",
        Description = "Valida el primer código generado por la app autenticadora. Si es correcto, habilita permanentemente el 2FA para el usuario."
    )]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> VerifyAndEnable([FromBody] VerifyTwoFactorDto dto)
    {
        var userId = GetUserId();
        var result = await _authService.EnableTwoFactorAsync(userId, dto.Code);

        if (result)
            return Ok(new { success = true, message = "2FA activado exitosamente" });
        else
            return BadRequest(new { success = false, message = "Código inválido" });
    }

    [HttpPost("disable")]
    [SwaggerOperation(
        Summary = "Desactiva el 2FA",
        Description = "Deshabilita la autenticación de dos pasos. Por seguridad, requiere ingresar un código 2FA válido actual."
    )]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> Disable([FromBody] DisableTwoFactorDto dto)
    {
        var userId = GetUserId();
        var result = await _authService.DisableTwoFactorAsync(userId, dto.Code);

        if (result)
            return Ok(new { success = true, message = "2FA desactivado exitosamente" });
        else
            return BadRequest(new { success = false, message = "Código inválido" });
    }

    [HttpGet("status")]
    [SwaggerOperation(
        Summary = "Consulta el estado del 2FA",
        Description = "Devuelve un valor booleano que indica si el usuario autenticado tiene activa la autenticación de dos factores."
    )]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult> Status()
    {
        var userId = GetUserId();
        var user = await _authService.GetUserByIdAsync(userId);

        return Ok(new
        {
            enabled = user?.TwoFactorEnabled ?? false
        });
    }

    [HttpPost("recovery-codes")]
    [SwaggerOperation(
        Summary = "Genera códigos de recuperación",
        Description = "Crea un nuevo set de códigos de uso único. Ideales por si el usuario pierde acceso a su dispositivo móvil."
    )]
    [ProducesResponseType(typeof(List<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<List<string>>> GenerateRecoveryCodes()
    {
        var userId = GetUserId();
        var codes = await _authService.GenerateTwoFactorRecoveryCodesAsync(userId);
        return Ok(new { recoveryCodes = codes });
    }
}