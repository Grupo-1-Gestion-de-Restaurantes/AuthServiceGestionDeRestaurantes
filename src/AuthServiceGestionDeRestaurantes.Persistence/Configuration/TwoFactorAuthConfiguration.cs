using AuthServiceGestionDeRestaurantes.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServiceGestionDeRestaurantes.Persistence.Configurations;

public class TwoFactorAuthConfiguration : IEntityTypeConfiguration<TwoFactorAuth>
{
    public void Configure(EntityTypeBuilder<TwoFactorAuth> builder)
    {
        builder.ToTable("two_factor_auth");

        builder.HasKey(t => t.Id);

        builder.Property(t => t.Id)
            .HasMaxLength(16)
            .ValueGeneratedOnAdd();

        builder.Property(t => t.UserId)
            .HasMaxLength(16)
            .IsRequired();

        builder.Property(t => t.SecretKey)
            .IsRequired()
            .HasMaxLength(256);

        builder.Property(t => t.IsEnabled)
            .HasDefaultValue(false);

        builder.Property(t => t.RecoveryCodes)
            .HasColumnType("jsonb");

        builder.HasOne(t => t.User)
            .WithOne(u => u.TwoFactorAuth)
            .HasForeignKey<TwoFactorAuth>(t => t.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(t => t.UserId)
            .IsUnique();
    }
}