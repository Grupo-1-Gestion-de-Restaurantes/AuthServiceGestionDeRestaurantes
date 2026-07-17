using System.Net;
using System.Text;
using AuthServiceGestionDeRestaurantes.Application.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Resend;

namespace AuthServiceGestionDeRestaurantes.Application.Services;

public class EmailService(
    IResend resend,
    IConfiguration configuration,
    ILogger<EmailService> logger) : IEmailService
{
    private const string BrandName = "Express";
    private const string BrandTagline = "Express Space Station";

    public async Task SendEmailVerificationAsync(string email, string username, string token)
    {
        var subject = $"Verifica tu correo · {BrandName}";
        var safeUsername = WebUtility.HtmlEncode(username);
        var verificationUrl = $"{GetFrontendUrl()}/verify-email?token={Uri.EscapeDataString(token)}";

        var bodyContent = $@"
            <p style=""margin:0 0 16px;color:#f0f0f2;font-size:16px;line-height:1.6;"">
              Hola <strong style=""color:#F1D302;"">{safeUsername}</strong>,
            </p>
            <p style=""margin:0 0 16px;color:#9ca3af;font-size:15px;line-height:1.6;"">
              Gracias por unirte a <strong style=""color:#f0f0f2;"">{BrandName}</strong>.
              Confirma tu correo para activar tu cuenta y empezar a explorar la estación.
            </p>
            <p style=""margin:0 0 8px;color:#9ca3af;font-size:13px;line-height:1.5;"">
              Este enlace expira en <strong style=""color:#f0f0f2;"">24 horas</strong>.
              Si no creaste esta cuenta, puedes ignorar este mensaje.
            </p>";

        var html = BuildEmailLayout(
            title: "Verifica tu correo",
            subtitle: "Un paso más para activar tu cuenta",
            bodyHtml: bodyContent,
            ctaLabel: "Verificar correo",
            ctaUrl: verificationUrl,
            ctaBackground: "#C1292E",
            ctaColor: "#FFFFFF",
            fallbackUrl: verificationUrl);

        await SendEmailAsync(email, subject, html);
    }

    public async Task SendPasswordResetAsync(string email, string username, string token)
    {
        var subject = $"Restablecer contraseña · {BrandName}";
        var safeUsername = WebUtility.HtmlEncode(username);
        var resetUrl = $"{GetFrontendUrl()}/reset-password?token={Uri.EscapeDataString(token)}";

        var bodyContent = $@"
            <p style=""margin:0 0 16px;color:#f0f0f2;font-size:16px;line-height:1.6;"">
              Hola <strong style=""color:#F1D302;"">{safeUsername}</strong>,
            </p>
            <p style=""margin:0 0 16px;color:#9ca3af;font-size:15px;line-height:1.6;"">
              Recibimos una solicitud para restablecer la contraseña de tu cuenta en {BrandName}.
              Si fuiste tú, usa el botón de abajo para elegir una nueva.
            </p>
            <p style=""margin:0 0 8px;color:#9ca3af;font-size:13px;line-height:1.5;"">
              Este enlace expira en <strong style=""color:#f0f0f2;"">1 hora</strong>.
              Si no solicitaste el cambio, ignora este correo y tu contraseña no se modificará.
            </p>";

        var html = BuildEmailLayout(
            title: "Restablecer contraseña",
            subtitle: "Solicitud de recuperación de acceso",
            bodyHtml: bodyContent,
            ctaLabel: "Restablecer contraseña",
            ctaUrl: resetUrl,
            ctaBackground: "#F1D302",
            ctaColor: "#111317",
            fallbackUrl: resetUrl);

        await SendEmailAsync(email, subject, html);
    }

    public async Task SendWelcomeEmailAsync(string email, string username)
    {
        var subject = $"¡Bienvenido a {BrandName}!";
        var safeUsername = WebUtility.HtmlEncode(username);
        var appUrl = GetFrontendUrl();

        var bodyContent = $@"
            <p style=""margin:0 0 16px;color:#f0f0f2;font-size:16px;line-height:1.6;"">
              ¡Hola <strong style=""color:#F1D302;"">{safeUsername}</strong>!
            </p>
            <p style=""margin:0 0 16px;color:#9ca3af;font-size:15px;line-height:1.6;"">
              Tu correo fue verificado y tu cuenta ya está activa.
              Ya puedes pedir, reservar mesas y explorar restaurantes en la red {BrandName}.
            </p>
            <p style=""margin:0 0 8px;color:#9ca3af;font-size:13px;line-height:1.5;"">
              Si tienes dudas, responde a este correo o contacta al equipo de soporte.
            </p>";

        var html = BuildEmailLayout(
            title: $"Bienvenido a {BrandName}",
            subtitle: "Tu cuenta está lista para despegar",
            bodyHtml: bodyContent,
            ctaLabel: "Ir a Express",
            ctaUrl: appUrl,
            ctaBackground: "#C1292E",
            ctaColor: "#FFFFFF",
            fallbackUrl: appUrl);

        await SendEmailAsync(email, subject, html);
    }

    private async Task SendEmailAsync(string to, string subject, string htmlBody)
    {
        var resendSettings = configuration.GetSection("ResendSettings");
        var enabled = bool.Parse(resendSettings["Enabled"] ?? "true");

        if (!enabled)
        {
            logger.LogInformation("Email disabled in configuration. Skipping send");
            return;
        }

        var apiKey = resendSettings["ApiKey"];
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            apiKey = Environment.GetEnvironmentVariable("RESEND_API_KEY");
        }

        if (string.IsNullOrWhiteSpace(apiKey))
        {
            logger.LogError("Resend API key is not configured (ResendSettings:ApiKey or RESEND_API_KEY)");
            throw new InvalidOperationException(
                "Resend API key is not configured. Set ResendSettings:ApiKey or environment variable RESEND_API_KEY.");
        }

        var fromEmail = resendSettings["FromEmail"];
        if (string.IsNullOrWhiteSpace(fromEmail))
        {
            var fromName = resendSettings["FromName"] ?? BrandName;
            fromEmail = $"{fromName} <onboarding@resend.dev>";
        }

        try
        {
            var message = new EmailMessage
            {
                From = fromEmail,
                Subject = subject,
                HtmlBody = htmlBody
            };
            message.To.Add(to);

            var response = await resend.EmailSendAsync(message);

            if (!response.Success)
            {
                var error = response.Exception;
                logger.LogError(error, "Resend failed to send email");
                throw new InvalidOperationException(
                    $"Resend failed to send email: {error?.Message ?? "unknown error"}",
                    error);
            }

            logger.LogInformation("Email sent successfully via Resend");
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            logger.LogError(ex, "Failed to send email via Resend");
            throw new InvalidOperationException($"Failed to send email: {ex.Message}", ex);
        }
    }

    private string GetFrontendUrl()
    {
        var url = configuration["AppSettings:FrontendUrl"]?.TrimEnd('/');
        return string.IsNullOrWhiteSpace(url) ? "http://localhost:5173" : url;
    }

    private static string BuildEmailLayout(
        string title,
        string subtitle,
        string bodyHtml,
        string ctaLabel,
        string ctaUrl,
        string ctaBackground,
        string ctaColor,
        string fallbackUrl)
    {
        var safeTitle = WebUtility.HtmlEncode(title);
        var safeSubtitle = WebUtility.HtmlEncode(subtitle);
        var safeCtaLabel = WebUtility.HtmlEncode(ctaLabel);
        var safeCtaUrl = WebUtility.HtmlEncode(ctaUrl);
        var safeFallback = WebUtility.HtmlEncode(fallbackUrl);
        var year = DateTime.UtcNow.Year;

        var sb = new StringBuilder();
        sb.Append($@"
<!DOCTYPE html>
<html lang=""es"">
<head>
  <meta charset=""utf-8"" />
  <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"" />
  <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"" />
  <title>{safeTitle}</title>
</head>
<body style=""margin:0;padding:0;background-color:#111317;font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;"">
  <table role=""presentation"" width=""100%"" cellpadding=""0"" cellspacing=""0"" border=""0"" style=""background-color:#111317;padding:32px 12px;"">
    <tr>
      <td align=""center"">
        <table role=""presentation"" width=""100%"" cellpadding=""0"" cellspacing=""0"" border=""0"" style=""max-width:560px;background-color:#16181f;border:1px solid rgba(255,255,255,0.08);border-radius:16px;overflow:hidden;"">
          <tr>
            <td style=""height:4px;background-color:#C1292E;font-size:0;line-height:0;"">&nbsp;</td>
          </tr>
          <tr>
            <td style=""padding:28px 28px 8px 28px;text-align:center;"">
              <div style=""font-family:Impact,Haettenschweiler,'Arial Black',sans-serif;font-size:28px;letter-spacing:0.12em;color:#f0f0f2;text-transform:uppercase;"">
                EXPRESS
              </div>
              <div style=""margin-top:6px;font-size:11px;font-weight:700;letter-spacing:0.28em;text-transform:uppercase;color:#F1D302;"">
                {WebUtility.HtmlEncode(BrandTagline)}
              </div>
            </td>
          </tr>
          <tr>
            <td style=""padding:20px 28px 8px 28px;text-align:center;"">
              <h1 style=""margin:0 0 8px;font-size:22px;line-height:1.3;color:#f0f0f2;font-weight:700;"">
                {safeTitle}
              </h1>
              <p style=""margin:0;color:#9ca3af;font-size:14px;line-height:1.5;"">
                {safeSubtitle}
              </p>
            </td>
          </tr>
          <tr>
            <td style=""padding:20px 28px 8px 28px;"">
              {bodyHtml}
            </td>
          </tr>
          <tr>
            <td align=""center"" style=""padding:20px 28px 8px 28px;"">
              <a href=""{safeCtaUrl}""
                 style=""display:inline-block;background-color:{ctaBackground};color:{ctaColor};text-decoration:none;font-weight:700;font-size:15px;letter-spacing:0.04em;padding:14px 28px;border-radius:10px;border:3px solid #000000;box-shadow:4px 4px 0 #000000;"">
                {safeCtaLabel}
              </a>
            </td>
          </tr>
          <tr>
            <td style=""padding:20px 28px 8px 28px;"">
              <p style=""margin:0 0 6px;color:#9ca3af;font-size:12px;line-height:1.5;"">
                Si el botón no funciona, copia y pega este enlace en tu navegador:
              </p>
              <p style=""margin:0;word-break:break-all;font-size:12px;line-height:1.5;"">
                <a href=""{safeFallback}"" style=""color:#F1D302;text-decoration:underline;"">{safeFallback}</a>
              </p>
            </td>
          </tr>
          <tr>
            <td style=""padding:28px;border-top:1px solid rgba(255,255,255,0.06);"">
              <p style=""margin:0 0 4px;color:rgba(245,245,247,0.4);font-size:11px;text-align:center;line-height:1.5;"">
                © {year} {WebUtility.HtmlEncode(BrandTagline)}. Todos los derechos reservados.
              </p>
              <p style=""margin:0;color:rgba(245,245,247,0.35);font-size:11px;text-align:center;line-height:1.5;"">
                La estación espacial de la gestión de restaurantes.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>");

        return sb.ToString();
    }
}
