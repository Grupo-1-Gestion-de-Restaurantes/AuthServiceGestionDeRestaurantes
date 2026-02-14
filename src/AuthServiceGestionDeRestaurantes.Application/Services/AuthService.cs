using AuthServiceGestionDeRestaurantes.Application.DTOs;
using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using AuthServiceGestionDeRestaurantes.Application.Exceptions;
using AuthServiceGestionDeRestaurantes.Application.Extensions;
using AuthServiceGestionDeRestaurantes.Application.Validators;
using AuthServiceGestionDeRestaurantes.Domain.Constants;
using AuthServiceGestionDeRestaurantes.Domain.Entities;
using AuthServiceGestionDeRestaurantes.Domain.Interfaces;
using AuthServiceGestionDeRestaurantes.Domain.Enums;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using AuthServiceGestionDeRestaurantes.Application.DTOs.Email;
using AuthServiceGestionDeRestaurantes.Application.DTOs.TwoFactor;

namespace AuthServiceGestionDeRestaurantes.Application.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly IPasswordHashService _passwordHashService;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly ICloudinaryService _cloudinaryService;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthService> _logger;
    private readonly ITwoFactorService _twoFactorService;

    public AuthService(
        IUserRepository userRepository,
        IRoleRepository roleRepository,
        IPasswordHashService passwordHashService,
        IJwtTokenService jwtTokenService,
        ICloudinaryService cloudinaryService,
        IEmailService emailService,
        IConfiguration configuration,
        ILogger<AuthService> logger,
        ITwoFactorService twoFactorService)
    {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _passwordHashService = passwordHashService;
        _jwtTokenService = jwtTokenService;
        _cloudinaryService = cloudinaryService;
        _emailService = emailService;
        _configuration = configuration;
        _logger = logger;
        _twoFactorService = twoFactorService;
    }

    public async Task<RegisterResponseDto> RegisterAsync(RegisterDto registerDto)
    {
        if (await _userRepository.ExistsByEmailAsync(registerDto.Email))
        {
            _logger.LogRegistrationWithExistingEmail();
            throw new BusinessException(ErrorCodes.EMAIL_ALREADY_EXISTS, "Email already exists");
        }

        if (await _userRepository.ExistsByUsernameAsync(registerDto.Username))
        {
            _logger.LogRegistrationWithExistingUsername();
            throw new BusinessException(ErrorCodes.USERNAME_ALREADY_EXISTS, "Username already exists");
        }

        string profilePicturePath;

        if (registerDto.ProfilePicture != null && registerDto.ProfilePicture.Size > 0)
        {
            var (isValid, errorMessage) = FileValidator.ValidateImage(registerDto.ProfilePicture);
            if (!isValid)
            {
                _logger.LogWarning($"File validation failed: {errorMessage}");
                throw new BusinessException(ErrorCodes.INVALID_FILE_FORMAT, errorMessage!);
            }

            try
            {
                var fileName = FileValidator.GenerateSecureFileName(registerDto.ProfilePicture.FileName);
                profilePicturePath = await _cloudinaryService.UploadImageAsync(registerDto.ProfilePicture, fileName);
            }
            catch (Exception)
            {
                _logger.LogImageUploadError();
                throw new BusinessException(ErrorCodes.IMAGE_UPLOAD_FAILED, "Failed to upload profile image");
            }
        }
        else
        {
            profilePicturePath = _cloudinaryService.GetDefaultAvatarUrl();
        }

        var emailVerificationToken = TokenGeneratorService.GenerateEmailVerificationToken();

        var userId = UuidGenerator.GenerateUserId();
        var userProfileId = UuidGenerator.GenerateUserId();
        var userEmailId = UuidGenerator.GenerateUserId();
        var userRoleId = UuidGenerator.GenerateUserId();

        var defaultRole = await _roleRepository.GetByNameAsync(RoleConstants.USER_ROLE);
        if (defaultRole == null)
        {
            throw new InvalidOperationException($"Default role '{RoleConstants.USER_ROLE}' not found.");
        }

        var user = new User
        {
            Id = userId,
            Name = registerDto.Name,
            Surname = registerDto.Surname,
            Username = registerDto.Username,
            Email = registerDto.Email.ToLowerInvariant(),
            Password = _passwordHashService.HashPassword(registerDto.Password),
            Status = false,
            UserProfile = new UserProfile
            {
                Id = userProfileId,
                UserId = userId,
                ProfilePicture = profilePicturePath,
                Phone = registerDto.Phone
            },
            UserEmail = new UserEmail
            {
                Id = userEmailId,
                UserId = userId,
                EmailVerified = false,
                EmailVerificationToken = emailVerificationToken,
                EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24)
            },
            UserRoles =
            [
                new Domain.Entities.UserRole
                {
                    Id = userRoleId,
                    UserId = userId,
                    RoleId = defaultRole.Id
                }
            ],
            UserPasswordReset = new UserPasswordReset
            {
                Id = UuidGenerator.GenerateUserId(),
                UserId = userId,
                PasswordResetToken = null,
                PasswordResetTokenExpiry = null
            },
        };

        var createdUser = await _userRepository.CreateAsync(user);
        _logger.LogUserRegistered(createdUser.Username);

        _ = Task.Run(async () =>
        {
            try
            {
                await _emailService.SendEmailVerificationAsync(createdUser.Email, createdUser.Username, emailVerificationToken);
                _logger.LogInformation("Verification email sent");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send verification email");
            }
        });

        return new RegisterResponseDto
        {
            Success = true,
            User = MapToUserResponseDto(createdUser),
            Message = "Usuario registrado exitosamente. Por favor, verifica tu email para activar la cuenta.",
            EmailVerificationRequired = true
        };
    }

    public async Task<AuthResponseDto> LoginAsync(LoginDto loginDto)
    {
        User? user = null;

        if (loginDto.EmailOrUsername.Contains('@'))
        {
            user = await _userRepository.GetByEmailAsync(loginDto.EmailOrUsername.ToLowerInvariant());
        }
        else
        {
            user = await _userRepository.GetByUsernameAsync(loginDto.EmailOrUsername);
        }

        if (user == null)
        {
            _logger.LogFailedLoginAttempt();
            throw new UnauthorizedAccessException("Invalid credentials");
        }

        if (!user.Status)
        {
            _logger.LogFailedLoginAttempt();
            throw new UnauthorizedAccessException("User account is disabled");
        }

        if (!_passwordHashService.VerifyPassword(loginDto.Password, user.Password))
        {
            _logger.LogFailedLoginAttempt();
            throw new UnauthorizedAccessException("Invalid credentials");
        }

        if (user.TwoFactorAuth?.IsEnabled == true)
        {
            return new AuthResponseDto
            {
                Success = true,
                Message = "Se requiere verificación de dos factores",
                RequiresTwoFactor = true,
                UserDetails = MapToUserDetailsDto(user),
                ExpiresAt = DateTime.UtcNow.AddMinutes(5)
            };
        }

        _logger.LogUserLoggedIn();

        var token = _jwtTokenService.GenerateToken(user);
        var expiryMinutes = int.Parse(_configuration["JwtSettings:ExpiryInMinutes"] ?? "30");

        return new AuthResponseDto
        {
            Success = true,
            Message = "Login exitoso",
            Token = token,
            UserDetails = MapToUserDetailsDto(user),
            ExpiresAt = DateTime.UtcNow.AddMinutes(expiryMinutes)
        };
    }

    private UserResponseDto MapToUserResponseDto(User user)
    {
        var userRole = user.UserRoles.FirstOrDefault()?.Role?.Name ?? RoleConstants.USER_ROLE;
        return new UserResponseDto
        {
            Id = user.Id,
            Name = user.Name,
            Surname = user.Surname,
            Username = user.Username,
            Email = user.Email,
            ProfilePicture = _cloudinaryService.GetFullImageUrl(user.UserProfile?.ProfilePicture ?? string.Empty),
            Phone = user.UserProfile?.Phone ?? string.Empty,
            Role = userRole,
            Status = user.Status,
            IsEmailVerified = user.UserEmail?.EmailVerified ?? false,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt,
            TwoFactorEnabled = user.TwoFactorAuth?.IsEnabled ?? false
        };
    }

    private UserDetailsDto MapToUserDetailsDto(User user)
    {
        return new UserDetailsDto
        {
            Id = user.Id,
            Username = user.Username,
            ProfilePicture = _cloudinaryService.GetFullImageUrl(user.UserProfile?.ProfilePicture ?? string.Empty),
            Role = user.UserRoles.FirstOrDefault()?.Role?.Name ?? RoleConstants.USER_ROLE,
            TwoFactorEnabled = user.TwoFactorAuth?.IsEnabled ?? false
        };
    }

    public async Task<EmailResponseDto> VerifyEmailAsync(VerifyEmailDto verifyEmailDto)
    {
        var user = await _userRepository.GetByEmailVerificationTokenAsync(verifyEmailDto.Token);
        if (user == null || user.UserEmail == null)
        {
            return new EmailResponseDto
            {
                Success = false,
                Message = "Invalid or expired verification token"
            };
        }

        user.UserEmail.EmailVerified = true;
        user.Status = true;
        user.UserEmail.EmailVerificationToken = null;
        user.UserEmail.EmailVerificationTokenExpiry = null;

        await _userRepository.UpdateAsync(user);

        try
        {
            await _emailService.SendWelcomeEmailAsync(user.Email, user.Username);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send welcome email to {Email}", user.Email);
        }

        _logger.LogInformation("Email verified successfully for user {Username}", user.Username);

        return new EmailResponseDto
        {
            Success = true,
            Message = "Email verificado exitosamente",
            Data = new
            {
                email = user.Email,
                verified = true
            }
        };
    }

    public async Task<EmailResponseDto> ResendVerificationEmailAsync(ResendVerificationDto resendDto)
    {
        var user = await _userRepository.GetByEmailAsync(resendDto.Email);
        if (user == null || user.UserEmail == null)
        {
            return new EmailResponseDto
            {
                Success = false,
                Message = "Usuario no encontrado",
                Data = new { email = resendDto.Email, sent = false }
            };
        }

        if (user.UserEmail.EmailVerified)
        {
            return new EmailResponseDto
            {
                Success = false,
                Message = "El email ya ha sido verificado",
                Data = new { email = user.Email, verified = true }
            };
        }

        var newToken = TokenGeneratorService.GenerateEmailVerificationToken();
        user.UserEmail.EmailVerificationToken = newToken;
        user.UserEmail.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24);

        await _userRepository.UpdateAsync(user);

        try
        {
            await _emailService.SendEmailVerificationAsync(user.Email, user.Username, newToken);
            return new EmailResponseDto
            {
                Success = true,
                Message = "Email de verificación enviado exitosamente",
                Data = new { email = user.Email, sent = true }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resend verification email to {Email}", user.Email);
            return new EmailResponseDto
            {
                Success = false,
                Message = "Error al enviar el email de verificación",
                Data = new { email = user.Email, sent = false }
            };
        }
    }

    public async Task<EmailResponseDto> ForgotPasswordAsync(ForgotPasswordDto forgotPasswordDto)
    {
        var user = await _userRepository.GetByEmailAsync(forgotPasswordDto.Email);
        if (user == null)
        {
            return new EmailResponseDto
            {
                Success = true,
                Message = "Si el email existe, se ha enviado un enlace de recuperación",
                Data = new { email = forgotPasswordDto.Email, initiated = true }
            };
        }

        var resetToken = TokenGeneratorService.GeneratePasswordResetToken();

        if (user.UserPasswordReset == null)
        {
            user.UserPasswordReset = new UserPasswordReset
            {
                UserId = user.Id,
                PasswordResetToken = resetToken,
                PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(1)
            };
        }
        else
        {
            user.UserPasswordReset.PasswordResetToken = resetToken;
            user.UserPasswordReset.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(1);
        }

        await _userRepository.UpdateAsync(user);

        try
        {
            await _emailService.SendPasswordResetAsync(user.Email, user.Username, resetToken);
            _logger.LogInformation("Password reset email sent to {Email}", user.Email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password reset email to {Email}", user.Email);
        }

        return new EmailResponseDto
        {
            Success = true,
            Message = "Si el email existe, se ha enviado un enlace de recuperación",
            Data = new { email = forgotPasswordDto.Email, initiated = true }
        };
    }

    public async Task<EmailResponseDto> ResetPasswordAsync(ResetPasswordDto resetPasswordDto)
    {
        var user = await _userRepository.GetByPasswordResetTokenAsync(resetPasswordDto.Token);
        if (user == null || user.UserPasswordReset == null)
        {
            return new EmailResponseDto
            {
                Success = false,
                Message = "Token de reset inválido o expirado",
                Data = new { token = resetPasswordDto.Token, reset = false }
            };
        }

        user.Password = _passwordHashService.HashPassword(resetPasswordDto.NewPassword);
        user.UserPasswordReset.PasswordResetToken = null;
        user.UserPasswordReset.PasswordResetTokenExpiry = null;

        await _userRepository.UpdateAsync(user);

        _logger.LogInformation("Password reset successfully for user {Username}", user.Username);

        return new EmailResponseDto
        {
            Success = true,
            Message = "Contraseña actualizada exitosamente",
            Data = new { email = user.Email, reset = true }
        };
    }

    public async Task<UserResponseDto?> GetUserByIdAsync(string userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return null;
        }

        return MapToUserResponseDto(user);
    }

    // ==================== MÉTODOS DE 2FA ====================

    public async Task<TwoFactorSetupDto> SetupTwoFactorAsync(string userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            throw new BusinessException("USER_NOT_FOUND", "Usuario no encontrado");
            
        return await _twoFactorService.GenerateSetupAsync(userId);
    }

    public async Task<bool> EnableTwoFactorAsync(string userId, string code)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            throw new BusinessException("USER_NOT_FOUND", "Usuario no encontrado");
            
        return await _twoFactorService.VerifyAndEnableAsync(userId, code);
    }

    public async Task<bool> DisableTwoFactorAsync(string userId, string code)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            throw new BusinessException("USER_NOT_FOUND", "Usuario no encontrado");
            
        return await _twoFactorService.DisableAsync(userId, code);
    }

    public async Task<bool> VerifyTwoFactorCodeAsync(string userId, string code)
    {
        return await _twoFactorService.VerifyCodeAsync(userId, code);
    }

    public async Task<List<string>> GenerateTwoFactorRecoveryCodesAsync(string userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            throw new BusinessException("USER_NOT_FOUND", "Usuario no encontrado");
            
        return await _twoFactorService.GenerateRecoveryCodesAsync(userId);
    }

    public async Task<string> GenerateTokenForUserAsync(string userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            throw new BusinessException("USER_NOT_FOUND", "Usuario no encontrado");
            
        return _jwtTokenService.GenerateToken(user);
    }
}