# filepath: /home/sprudel/insecure-app/Dockerfile
# Use the .NET SDK image to build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /source

# Copy the solution file and restore dependencies
COPY *.sln .
COPY M183/*.csproj ./M183/
RUN dotnet restore

# Copy the rest of the application code
COPY . .
WORKDIR /source/M183
RUN dotnet publish -c Release -o /app/publish --no-restore

# Use the .NET runtime image for the final stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# Expose the ports the app listens on
EXPOSE 80
EXPOSE 443

# Set the entry point for the application
ENTRYPOINT ["dotnet", "M183.dll"]