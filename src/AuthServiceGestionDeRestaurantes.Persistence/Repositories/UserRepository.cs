using System.Data;
using AuthServiceGestionDeRestaurantes.Application.Services;
using AuthServiceGestionDeRestaurantes.Domain.Entities;
using AuthServiceGestionDeRestaurantes.Domain.Interfaces;
using AuthServiceGestionDeRestaurantes.Persistence.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthServiceGestionDeRestaurantes.Persistence.Repositories;

public class UserRepository : IUserRepository
{
    private readonly ApplicationDbContext context;
    private readonly ILogger<UserRepository> _logger;

    public UserRepository(ApplicationDbContext context, ILogger<UserRepository> logger)
    {
        this.context = context;
        _logger = logger;
    }

    public async Task<User> GetByIdAsync(string id)
    {
        var user = await context.Users
            .Include(u => u.UserProfile)
            .Include(u => u.UserEmail)
            .Include(u => u.UserPasswordReset)
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .Include(u => u.TwoFactorAuth)  
            .FirstOrDefaultAsync(u => u.Id == id);
            
        return user ?? throw new InvalidOperationException($"User with id {id} not found.");
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        return await context.Users
            .Include(u => u.UserProfile)
            .Include(u => u.UserEmail)
            .Include(u => u.UserPasswordReset)
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .Include(u => u.TwoFactorAuth)
            .FirstOrDefaultAsync(u => EF.Functions.ILike(u.Email, email));
    }

    public async Task<User?> GetByUsernameAsync(string username)
    {
        return await context.Users
            .Include(u => u.UserProfile)
            .Include(u => u.UserEmail)
            .Include(u => u.UserPasswordReset)
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .Include(u => u.TwoFactorAuth)
            .FirstOrDefaultAsync(u => EF.Functions.ILike(u.Username, username));
    }

    public async Task<User?> GetByEmailVerificationTokenAsync(string token)
    {
        return await context.Users
            .Include(u => u.UserProfile)
            .Include(u => u.UserEmail)
            .Include(u => u.UserPasswordReset)
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.UserEmail != null && 
                                    u.UserEmail.EmailVerificationToken == token &&
                                    u.UserEmail.EmailVerificationTokenExpiry > DateTime.UtcNow);
    }

    public async Task<User?> GetByPasswordResetTokenAsync(string token)
    {
        return await context.Users
            .Include(u => u.UserProfile)
            .Include(u => u.UserEmail)
            .Include(u => u.UserPasswordReset)
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.UserPasswordReset != null && 
                                    u.UserPasswordReset.PasswordResetToken == token &&
                                    u.UserPasswordReset.PasswordResetTokenExpiry > DateTime.UtcNow);
    }

    public async Task<User> CreateAsync(User user)
    {
        context.Users.Add(user);
        await context.SaveChangesAsync();
        return await GetByIdAsync(user.Id);
    }

    public async Task<User> UpdateAsync(User user)
    {
        await context.SaveChangesAsync();
        return await GetByIdAsync(user.Id);
    }

    public async Task<bool> DeleteAsync(string id)
    {
        var user = await GetByIdAsync(id);
        context.Users.Remove(user);
        await context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> ExistsByEmailAsync(string email)
    {
        return await context.Users
            .AnyAsync(u => EF.Functions.ILike(u.Email, email));
    }

    public async Task<bool> ExistsByUsernameAsync(string username)
    {
        return await context.Users
            .AnyAsync(u => EF.Functions.ILike(u.Username, username));
    }

    public async Task UpdateUserRoleAsync(string userId, string roleId)
    {
        var existingRoles = await context.UserRoles
            .Where(ur => ur.UserId == userId)
            .ToListAsync();

        context.UserRoles.RemoveRange(existingRoles);

        var newUserRole = new UserRole
        {
            Id = UuidGenerator.GenerateUserId(),
            UserId = userId,
            RoleId = roleId,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        context.UserRoles.Add(newUserRole);
        await context.SaveChangesAsync();
    }

    public async Task AddTwoFactorAuthAsync(TwoFactorAuth twoFactorAuth)
    {
        await context.TwoFactorAuths.AddAsync(twoFactorAuth);
        await context.SaveChangesAsync();
    }

    public async Task DeleteTwoFactorAuthAsync(string twoFactorAuthId)
    {
        var twoFactorAuth = await context.TwoFactorAuths.FindAsync(twoFactorAuthId);
        if (twoFactorAuth != null)
        {
            context.TwoFactorAuths.Remove(twoFactorAuth);
            await context.SaveChangesAsync();
        }
    }
}