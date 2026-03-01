using System;
using AuthServiceGestionDeRestaurantes.Application.DTOs;
using AuthServiceGestionDeRestaurantes.Application.DTOs.Email;
using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;
using AuthServiceGestionDeRestaurantes.Domain.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;


namespace AuthServiceGestionDeRestaurantes.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class AuthController(IAuthService authService) : ControllerBase
{
    [HttpGet("profile")]
    [Authorize]
    public async Task<ActionResult<object>> GetProfile()
    {
        var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == "sub" || c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
        if (userIdClaim == null || string.IsNullOrEmpty(userIdClaim.Value))
        {
            return Unauthorized();
        }

        var user = await authService.GetUserByIdAsync(userIdClaim.Value);
        if (user == null)
        {
            return NotFound();
        }
        return Ok(new
        {
            success = true,
            message = "Perfil obtenido exitosamente",
            data = user
        });
    }
    [HttpPost("register")]
    [RequestSizeLimit(10 * 1024 * 1024)] // 10MB límite
    [EnableRateLimiting("AuthPolicy")]
    public async Task<ActionResult<RegisterResponseDto>> Register([FromForm] RegisterDto registerDto)
    {
        var result = await authService.RegisterAsync(registerDto);
        // Devolver 201 Created para registro
        return StatusCode(201, result);
    }

    [HttpPost("login")]
    [EnableRateLimiting("AuthPolicy")]
    public async Task<ActionResult<AuthResponseDto>> Login([FromBody] LoginDto loginDto)
    {
        var result = await authService.LoginAsync(loginDto);
        return Ok(result);
    }

    [HttpPost("verify-email")]
    [EnableRateLimiting("ApiPolicy")]
    public async Task<ActionResult<EmailResponseDto>> VerifyEmail([FromBody] VerifyEmailDto verifyEmailDto)
    {
        var result = await authService.VerifyEmailAsync(verifyEmailDto);
        return Ok(result);
    }

    [HttpPost("resend-verification")]
    [EnableRateLimiting("AuthPolicy")]
    public async Task<ActionResult<EmailResponseDto>> ResendVerification([FromBody] ResendVerificationDto resendDto)
    {
        var result = await authService.ResendVerificationEmailAsync(resendDto);

        // Return appropriate status code based on result
        if (!result.Success)
        {
            if (result.Message.Contains("no encontrado", StringComparison.OrdinalIgnoreCase))
            {
                return NotFound(result);
            }
            if (result.Message.Contains("ya ha sido verificado", StringComparison.OrdinalIgnoreCase) ||
                result.Message.Contains("ya verificado", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest(result);
            }
            // Email sending failed - Service Unavailable
            return StatusCode(503, result);
        }

        return Ok(result);
    }

    [HttpPost("forgot-password")]
    [EnableRateLimiting("AuthPolicy")]
    public async Task<ActionResult<EmailResponseDto>> ForgotPassword([FromBody] ForgotPasswordDto forgotPasswordDto)
    {
        var result = await authService.ForgotPasswordAsync(forgotPasswordDto);

        // ForgotPassword always returns success for security (even if user not found)
        // But if email sending fails, return 503
        if (!result.Success)
        {
            return StatusCode(503, result);
        }

        return Ok(result);
    }

    [HttpPost("reset-password")]
    [EnableRateLimiting("AuthPolicy")]
    public async Task<ActionResult<EmailResponseDto>> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
    {
        var result = await authService.ResetPasswordAsync(resetPasswordDto);
        return Ok(result);
    }

    [HttpPost("verify-2fa")]
    [EnableRateLimiting("AuthPolicy")]
    public async Task<ActionResult<AuthResponseDto>> VerifyTwoFactor([FromBody] VerifyTwoFactorDto dto)
    {
        var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == "sub" || c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");

        if (userIdClaim == null || string.IsNullOrEmpty(userIdClaim.Value))
        {
            return Unauthorized(new { success = false, message = "Usuario no autenticado" });
        }

        var isValid = await authService.VerifyTwoFactorCodeAsync(userIdClaim.Value, dto.Code);

        if (!isValid)
        {
            return Unauthorized(new { success = false, message = "Código 2FA inválido" });
        }

        var user = await authService.GetUserByIdAsync(userIdClaim.Value);
        if (user == null)
        {
            return NotFound(new { success = false, message = "Usuario no encontrado" });
        }
        var token = await authService.GenerateTokenForUserAsync(userIdClaim.Value);

        return Ok(new AuthResponseDto
        {
            Success = true,
            Message = "Login exitoso",
            Token = token,
            UserDetails = new UserDetailsDto
            {
                Id = user.Id,
                Username = user.Username,
                ProfilePicture = user.ProfilePicture,
                Role = user.Role,
                TwoFactorEnabled = true
            },
            ExpiresAt = DateTime.UtcNow.AddMinutes(30),
            RequiresTwoFactor = false
        });
    }

    // Enpoint para registrar un nuevo empleado. Requiere rol de MANAGER_ROLE o ADMIN_ROLE
    [HttpPost("register-employee")]
    [Authorize]
    [RequestSizeLimit(10 * 1024 * 1024)] // 10MB límite
    [EnableRateLimiting("AuthPolicy")]
    public async Task<ActionResult<UserResponseDto>> RegisterEmployee([FromForm] RegisterEmployeeDto dto)
    {

        var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == "sub" || c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
        if (userIdClaim == null || string.IsNullOrEmpty(userIdClaim.Value))
        {
            return Unauthorized();
        }

        var user = await authService.GetUserByIdAsync(userIdClaim.Value);
        if (user == null)
        {
            return NotFound();
        }

        // Validar que el usuario tenga rol de MANAGER_ROLE o ADMIN_ROLE
        if (user.Role != RoleConstants.MANAGER_ROLE && user.Role != RoleConstants.ADMIN_ROLE)
        {
            return Forbid();
        }

        //validar que el rol a asignar sea EMPLOYEE_ROLE o MANAGER_ROLE (pero solo ADMIN_ROLE puede asignar MANAGER_ROLE)
        if (dto.Role != RoleConstants.EMPLOYEE_ROLE && dto.Role != RoleConstants.MANAGER_ROLE)
        {
            return BadRequest(new { success = false, message = "Rol inválido. Solo se permiten EMPLOYEE_ROLE o MANAGER_ROLE" });
        }
        if (dto.Role == RoleConstants.MANAGER_ROLE && user.Role != RoleConstants.ADMIN_ROLE)
        {
            return Unauthorized(new { success = false, message = "Solo usuarios con rol ADMIN_ROLE pueden asignar el rol MANAGER_ROLE" });
        }

        var result = await authService.RegisterEmployeeAsync(dto);
        return Ok(result);
    }

    [HttpDelete("rollbackUser/{id}")]
    [Authorize]
    public async Task<IActionResult> HardDeleteForRollBack(string id)
    {

        var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == "sub" || c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
        if (userIdClaim == null || string.IsNullOrEmpty(userIdClaim.Value))
        {
            return Unauthorized();
        }

        var user = await authService.GetUserByIdAsync(userIdClaim.Value);
        if (user == null)
        {
            return NotFound();
        }

        // Validar que tenga rol de MANAGER_ROLE o ADMIN_ROLE
        if (user.Role != RoleConstants.MANAGER_ROLE && user.Role != RoleConstants.ADMIN_ROLE)
        {
            return Forbid();
        }

        var success = await authService.HardDeleteForRollBackAsync(id);
        if (!success)
        {
            return NotFound(new { success = false, message = "Usuario no encontrado o no se pudo eliminar" });
        }
        return Ok(new { success = true, message = "Usuario eliminado correctamente." });
    }

}
