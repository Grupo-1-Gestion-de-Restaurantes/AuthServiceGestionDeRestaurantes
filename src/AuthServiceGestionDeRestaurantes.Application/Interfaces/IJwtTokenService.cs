
using AuthServiceGestionDeRestaurantes.Domain.Entities;

namespace AuthServiceGestionDeRestaurantes.Application.Interfaces;

public interface IJwtTokenService
{
    string GenerateToken(User user);
}