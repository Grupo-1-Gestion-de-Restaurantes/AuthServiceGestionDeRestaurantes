namespace AuthServiceGestionDeRestaurantes.Domain.Constants;

public static class RoleConstants
{
    public const string ADMIN_ROLE = "ADMIN_ROLE";
    public const string CLIENT_ROLE = "CLIENT_ROLE";
    public const string MANAGER_ROLE = "MANAGER_ROLE";
    public const string EMPLOYEE_ROLE = "EMPLOYEE_ROLE";

    public static readonly string[] AllowedRoles = [ADMIN_ROLE, CLIENT_ROLE, MANAGER_ROLE, EMPLOYEE_ROLE];
}