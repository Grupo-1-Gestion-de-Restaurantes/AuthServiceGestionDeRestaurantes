using AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;
using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthServiceGestionDeRestaurantes.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
[Authorize]
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
    public async Task<ActionResult<TwoFactorSetupDto>> Setup()
    {
        var userId = GetUserId();
        var result = await _authService.SetupTwoFactorAsync(userId);
        return Ok(result);
    }

    [HttpPost("verify-and-enable")]
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
    public async Task<ActionResult> Status()
    {
        var userId = GetUserId();
        var user = await _authService.GetUserByIdAsync(userId);
        
        return Ok(new { 
            enabled = user?.TwoFactorEnabled ?? false 
        });
    }

    [HttpPost("recovery-codes")]
    public async Task<ActionResult<List<string>>> GenerateRecoveryCodes()
    {
        var userId = GetUserId();
        var codes = await _authService.GenerateTwoFactorRecoveryCodesAsync(userId);
        return Ok(new { recoveryCodes = codes });
    }
}