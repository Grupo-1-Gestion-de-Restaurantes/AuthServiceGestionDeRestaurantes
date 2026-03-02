using AuthServiceGestionDeRestaurantes.Application.DTOs;
using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using AuthServiceGestionDeRestaurantes.Domain.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Swashbuckle.AspNetCore.Annotations;

namespace AuthServiceGestionDeRestaurantes.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
[SwaggerTag("Endpoints para gestión de usuarios y roles")]
public class UsersController(IUserManagementService userManagementService) : ControllerBase
{
    private async Task<bool> CurrentUserIsAdmin()
    {
        var userId = User.Claims.FirstOrDefault(c => c.Type == "sub" || c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;
        if (string.IsNullOrEmpty(userId)) return false;
        var roles = await userManagementService.GetUserRolesAsync(userId);
        return roles.Contains(RoleConstants.ADMIN_ROLE);
    }

    [HttpPut("{userId}/role")]
    [Authorize]
    [EnableRateLimiting("ApiPolicy")]
    [SwaggerOperation(Summary = "Actualiza el rol de un usuario", Description = "Solo los administradores pueden actualizar el rol de otros usuarios.")]
    public async Task<ActionResult<UserResponseDto>> UpdateUserRole(string userId, [FromBody] UpdateUserRoleDto dto)
    {
        if (!await CurrentUserIsAdmin())
        {
            return StatusCode(403, new { success = false, message = "Forbidden" });
        }

        var result = await userManagementService.UpdateUserRoleAsync(userId, dto.RoleName);
        return Ok(result);
    }

    [HttpGet("{userId}/roles")]
    [Authorize]
    [SwaggerOperation(Summary = "Obtiene los roles de un usuario", Description = "Devuelve una lista con los roles asignados a un usuario específico.")]
    public async Task<ActionResult<IReadOnlyList<string>>> GetUserRoles(string userId)
    {
        var roles = await userManagementService.GetUserRolesAsync(userId);
        return Ok(roles);
    }

    [HttpGet("by-role/{roleName}")]
    [Authorize]
    [EnableRateLimiting("ApiPolicy")]
    [SwaggerOperation(Summary = "Obtiene usuarios por rol", Description = "Devuelve una lista de usuarios que pertenecen a un rol específico. Solo los administradores pueden acceder a esta funcionalidad.")]
    public async Task<ActionResult<IReadOnlyList<UserResponseDto>>> GetUsersByRole(string roleName)
    {
        if (!await CurrentUserIsAdmin())
        {
            return StatusCode(403, new { success = false, message = "Forbidden" });
        }

        var users = await userManagementService.GetUsersByRoleAsync(roleName);
        return Ok(users);
    }
}
