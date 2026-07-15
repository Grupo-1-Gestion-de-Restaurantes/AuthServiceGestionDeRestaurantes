using AuthServiceGestionDeRestaurantes.Domain.Entities;
using AuthServiceGestionDeRestaurantes.Application.Services;
using AuthServiceGestionDeRestaurantes.Domain.Constants;
using Microsoft.EntityFrameworkCore;

namespace AuthServiceGestionDeRestaurantes.Persistence.Data;

public static class DataSeeder
{
    public static async Task SeedAsync(ApplicationDbContext context)
    {
        if(!context.Roles.Any())
        {
            var roles = new List<Role>
            {
                new()
                {
                    Id = UuidGenerator.GenerateRoleId(),
                        Name = RoleConstants.ADMIN_ROLE
                },
                new()
                {
                    Id = UuidGenerator.GenerateRoleId(),
                        Name = RoleConstants.CLIENT_ROLE
                },
                new()
                {
                    Id = UuidGenerator.GenerateRoleId(),
                        Name = RoleConstants.MANAGER_ROLE
                },
                new()
                {
                    Id = UuidGenerator.GenerateRoleId(),
                        Name = RoleConstants.EMPLOYEE_ROLE
                },
            };

            await context.Roles.AddRangeAsync(roles);
            await context.SaveChangesAsync();
        }

        await EnsureDemoUserAsync(context, "admin1", "admin@gestion.local", "ADMIN123", "Admin", "User", string.Empty, RoleConstants.ADMIN_ROLE);
        await EnsureDemoUserAsync(context, "cliente1", "cliente@gestion.local", "CLIENTE123", "Cliente", "Demo", "12345678", RoleConstants.CLIENT_ROLE);
    }

    private static async Task EnsureDemoUserAsync(
        ApplicationDbContext context,
        string username,
        string email,
        string password,
        string name,
        string surname,
        string phone,
        string roleName)
    {
        var existing = await context.Users.FirstOrDefaultAsync(u => u.Email == email || u.Username == username);
        if (existing != null) return;

        var role = await context.Roles.FirstOrDefaultAsync(r => r.Name == roleName);
        if (role == null) return;

        var passwordHasher = new PasswordHashService();
        var userId = UuidGenerator.GenerateUserId();

        var user = new User
        {
            Id = userId,
            Name = name,
            Surname = surname,
            Username = username,
            Email = email,
            Password = passwordHasher.HashPassword(password),
            Status = true,
            UserProfile = new UserProfile
            {
                Id = UuidGenerator.GenerateUserId(),
                UserId = userId,
                ProfilePicture = string.Empty,
                Phone = phone
            },
            UserEmail = new UserEmail
            {
                Id = UuidGenerator.GenerateUserId(),
                UserId = userId,
                EmailVerified = true,
                EmailVerificationToken = null,
                EmailVerificationTokenExpiry = null
            },
            UserRoles =
            [
                new UserRole
                {
                    Id = UuidGenerator.GenerateUserId(),
                    UserId = userId,
                    RoleId = role.Id
                }
            ]
        };

        await context.Users.AddAsync(user);
        await context.SaveChangesAsync();
    }
}