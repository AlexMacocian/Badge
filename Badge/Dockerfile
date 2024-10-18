#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
# Install clang/zlib1g-dev dependencies for publishing to native
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    clang zlib1g-dev
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY . /src/Badge/
WORKDIR "/src/Badge"
RUN dotnet restore
RUN dotnet clean
RUN dotnet build -c $BUILD_CONFIGURATION -o /app/build
RUN dotnet publish Badge.csproj -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=true -v detailed
RUN dotnet --info >> /app/publish/dotnet.info

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0 AS final
ENV ASPNETCORE_ENVIRONMENT=Production
WORKDIR /app
EXPOSE 8080 443
COPY --from=build /app/publish .
ENTRYPOINT ["./Badge"]