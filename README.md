# M183 - Insecure App

## Datenbank aufsetzen
- Projekt im Visual Studio öffnen
- Paket-Manager-Konsole öffnen

![Screenshot: Paket-Manager-Konsole öffnen](/img/paket-manager-konsole.png?raw=true "Screenshot: Paket-Manager-Konsole öffnen")  

- Befehl `Update-Database` ausführen

## Datenbankzugriff im Visual Studio
- Server-Explorer öffnen

![Screenshot: Server-Explorer öffnen](/img/server-explorer.png?raw=true "Screenshot: Server-Explorer öffnen")

- "Mit Datenbank verbinden" klicken (1)
- Servername: (localdb)\mssqllocaldb (2)
- In der Box "Mit Datenbank verbinden": Datenbanknamen auswählen oder ausgeben auf den Pfeil klicken (3)
- Datenbank "M183InsecureApp" auswählen und verbinden

![Screenshot: Datenbankvrbindung hinzufügen](/img/datenbank-verbindung-hinzufuegen.png?raw=true "Screenshot: Datenbankvrbindung hinzufügen")

## Benutzer in der Applikation:
1. Benutzername: **administrator** Passwort: **8dminSec**
2. Benutzername: **user** Passwort: **uS3rP8ss**

## Troubleshooting

### MySQL statt MSSQLLocalDB verwenden

Wenn MSSQLLocalDB nicht läuft (z.B. auf Mac OS) kann auch MySQL (oder ein anderer Datenbankserver) verwendet werden.

**Achtung:** Wenn Sie einen anderen Datenbankserver verwenden, werden alle Lösungen welche Migrations oder SQL Code beinhalten möglicherweise nicht mehr 1:1 funktionieren.

1. Eine MySQL Datenbank für das Projekt erstellen
2. Im NuGet Paketmanager folgende Abhängigkeit einfügen: ``Pomelo.EntityFrameworkCore.MySql``
3. Den Connection String in der Datei ``appsettings.json`` anpassen. Je nach Konfiguration müssen User + Passwort auch angepasst werden.
```
  "ConnectionStrings": {
    "SongContext": "Server=localhost;Database={IhrDatenbankName};User=root;Password="
  },
```

4. Im Program.cs die MySql Datenbank anbinden

**Anbindung für MSSQL (alt):**

```
builder.Services.AddDbContext<NewsAppContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("SongContext")));
```

**Anbindung für MySQL (neu):**

```
string connectionString = builder.Configuration.GetConnectionString("SongContext");
builder.Services.AddDbContext<NewsAppContext>(options =>
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString)));
```

5. Alle Dateien im Ordner ``Migrations`` löschen
6. Mit dem Befehl ``Add-Migration CreateDatabase`` neue Migrations für MySQL anlegen 
7. Die Datenbank mit ``Update-Database`` erstellen.

### Keine Paketmanager-Konsole vorhanden

Bei Mac OS oder wenn man eine andere IDE verwendet gibt es ggf. keine Paketmanager-Konsole. Als Alternative kann das ``dotnet`` CLI in einer normalen Shell / PowerShell wie folgt verwendet werden.

1. dotnet-ef installieren
```
dotnet tool install --global dotnet-ef
```

2. Alternative für ``Update-Database``
```
dotnet ef database update
```

1. Alternative für ``Create-Migration``
```
dotnet ef migrations add "MigrationName"
```