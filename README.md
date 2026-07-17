# Sistema Gestión de Restaurantes AuthService - Grupo 1

Este proyecto es el microservicio de autenticación y seguridad desarrollado en C# y .NET 8 para el Sistema de Gestión de Restaurantes. Se encarga del control de acceso, registro de usuarios, roles y seguridad avanzada (2FA), delegando los tokens JWT al resto de microservicios del sistema.

## Tecnologías Utilizadas

El sistema está construido sobre el ecosistema de Microsoft utilizando **C#** con el framework **.NET 8**. La persistencia de datos relacional se maneja mediante **PostgreSQL** y **Entity Framework Core (EF Core)**. Para la seguridad, se implementan **JSON Web Tokens (JWT)**, limitadores de peticiones (Rate Limiting) y encriptación de contraseñas. El almacenamiento de imágenes de perfil se logra mediante la integración con la API de **Cloudinary** y la documentación interactiva es provista por **Swagger**.

## Instalación y Configuración

## Configuración de appsettings

El sistema depende de configuraciones críticas para funcionar. La base de datos corre en el puerto 5435 localmente. El secreto del JWT, las credenciales de Cloudinary y la **API key de Resend** (envío de correos) deben configurarse de forma segura.

### Correos con Resend

El AuthService envía correos transaccionales (verificación, reset de contraseña y bienvenida) mediante la [API de Resend](https://resend.com), no SMTP. Así funciona de forma fiable en Railway y otros PaaS.

En `appsettings.json` solo va la **estructura** (sin secretos reales):

```json
"ResendSettings": {
  "ApiKey": "",
  "FromEmail": "Express <onboarding@resend.dev>",
  "FromName": "Express",
  "Enabled": true
}
```

| Entorno | Dónde poner la API key |
| --- | --- |
| Local | `appsettings.Development.json` (ignorado por git) o variable `ResendSettings__ApiKey` / `RESEND_API_KEY` |
| Railway / producción | Variables de entorno (nunca en el repositorio) |

**Variables recomendadas en Railway:**

```
ResendSettings__ApiKey=re_xxxxxxxx
ResendSettings__FromEmail=Express <onboarding@resend.dev>
ResendSettings__FromName=Express
ResendSettings__Enabled=true
AppSettings__FrontendUrl=https://tu-frontend.web.app
```

Notas:

- Sin dominio verificado en Resend, usa `onboarding@resend.dev` como remitente de prueba.
- Con dominio verificado: `Express <noreply@tudominio.com>`.
- `AppSettings:FrontendUrl` debe ser la URL pública del cliente (los links de verificación/reset la usan).
- **Nunca** subas la API key real a git ni la dejes hardcodeada en `appsettings.json`.

## Instalación y Ejecución

1. Clonar el repositorio en el entorno local.
2. Revisar `appsettings.json` (JWT, Cloudinary, base de datos) y configurar Resend de forma segura (User Secrets, `appsettings.Development.json` o variables de entorno).
3. Levantar el contenedor de la base de datos PostgreSQL ejecutando el comando `docker compose up -d`.
4. Compilar la solución para restaurar las dependencias ejecutando `dotnet build`.
5. Iniciar el servidor ejecutando `dotnet run --project .\src\AuthServiceGestionDeRestaurantes.Api\`.


## Características Principales
### Funciones de Administrador
El sistema se inicializa con un rol de administrador por defecto. Los usuarios con este rol tienen permisos exclusivos para gestionar a los empleados. Pueden actualizar y asignar roles dinámicamente a cualquier usuario registrado mediante su ID. Además, cuentan con la capacidad de realizar consultas filtradas para obtener listas completas de usuarios que pertenecen a un rol específico dentro del restaurante.

### Funciones de Cliente / Empleado
Los usuarios pueden crear su cuenta subiendo directamente su imagen de perfil a la nube. Deben verificar su correo electrónico mediante un código numérico para garantizar la propiedad de la cuenta. Además, pueden elevar la seguridad habilitando la Autenticación de Dos Factores (2FA) compatible con Google Authenticator/Authy, generando códigos de recuperación en caso de perder acceso a su dispositivo móvil.

## Documentación
En la entrega se adjuntan colecciones de Postman. Para ir a la documentación con swager acceda a : [swagger](http://localhost:5233/swagger/index.html)
** edite el puerto según lo haya puesto en el .env

## Rutas Principales (Endpoints)

| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| **POST** | `/api/v1/auth/login` | Inicia sesión y devuelve un token JWT (o pide 2FA) |
| **POST** | `/api/v1/auth/register` | Registra un usuario nuevo con imagen de perfil (Form-Data) |
| **GET** | `/api/v1/auth/profile` | Obtiene la información del perfil del usuario autenticado |
| **POST** | `/api/v1/auth/verify-email` | Verifica la cuenta del usuario mediante un código PIN |
| **POST** | `/api/v1/twofactor/setup` | Genera la llave y código QR para configurar el 2FA |
| **PUT** | `/api/v1/users/{userId}/role` | (Admin) Asigna o actualiza el rol de un usuario existente |
| **GET** | `/api/v1/health` | Verifica el estado y salud del microservicio |
