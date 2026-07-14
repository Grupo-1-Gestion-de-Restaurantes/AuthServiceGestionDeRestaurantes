# =============================================================================
# AuthServiceGestionDeRestaurantes — multi-stage Dockerfile (.NET 8)
# Build context: ./AuthServiceGestionDeRestaurantes
# =============================================================================

# ----- Stage: build (SDK completo para restore + publish) -----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copiar manifests primero → maximiza caché de capas en restore
COPY AuthServiceGestionDeRestaurantes.sln ./
COPY src/AuthServiceGestionDeRestaurantes.Domain/AuthServiceGestionDeRestaurantes.Domain.csproj \
     src/AuthServiceGestionDeRestaurantes.Domain/
COPY src/AuthServiceGestionDeRestaurantes.Application/AuthServiceGestionDeRestaurantes.Application.csproj \
     src/AuthServiceGestionDeRestaurantes.Application/
COPY src/AuthServiceGestionDeRestaurantes.Persistence/AuthServiceGestionDeRestaurantes.Persistence.csproj \
     src/AuthServiceGestionDeRestaurantes.Persistence/
COPY src/AuthServiceGestionDeRestaurantes.Api/AuthServiceGestionDeRestaurantes.Api.csproj \
     src/AuthServiceGestionDeRestaurantes.Api/

RUN dotnet restore src/AuthServiceGestionDeRestaurantes.Api/AuthServiceGestionDeRestaurantes.Api.csproj

# Código fuente completo
COPY src/ ./src/

RUN dotnet publish src/AuthServiceGestionDeRestaurantes.Api/AuthServiceGestionDeRestaurantes.Api.csproj \
    -c Release \
    -o /app/publish \
    /p:UseAppHost=false \
    --no-restore

# ----- Stage: development (hot reload con dotnet watch) -----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS development
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src ./
ENV ASPNETCORE_URLS=http://+:5233
ENV ASPNETCORE_ENVIRONMENT=Development
EXPOSE 5233
WORKDIR /src/src/AuthServiceGestionDeRestaurantes.Api
ENTRYPOINT ["dotnet", "watch", "run", "--no-launch-profile", "--urls", "http://+:5233"]

# ----- Stage: production (solo runtime ASP.NET) -----
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS production
WORKDIR /app

# curl para healthcheck de Compose
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

ENV ASPNETCORE_URLS=http://+:5233
ENV ASPNETCORE_ENVIRONMENT=Production
EXPOSE 5233

COPY --from=build /app/publish .

# Directorio para Data Protection keys (SecurityExtensions)
RUN mkdir -p /app/keys && chmod 777 /app/keys

ENTRYPOINT ["dotnet", "AuthServiceGestionDeRestaurantes.Api.dll"]
