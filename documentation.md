# Introduction

This is a portfolio about the LB 183 applications security. Here I will describe what I did in this module + document everything. Firstly, we analyze threat scenariosn and the risk for ransomware attacks. Then we look closer to SQL Injections and how to fix this security risk. The we implement a JWT and 2FA. For Humanfactor security we will implement some password rules and to finish this thing we will implement some logging. 

# HZ1

#### Evaluation of Three Threat Scenarios

| **Threat Scenario**         | **Confidentiality** | **Integrity** | **Availability** |
| --------------------------- | ------------------- | ------------- | ---------------- |
| Ransomware Attack           | 1                   | 2             | 2                |
| Insider Attack (Data Theft) | 2                   | 1             | 0                |
| SQL Injection Attack        | 1                   | 2             | 1                |

---

#### Risk Analysis for Ransomware Attack

| **Risk Factor**     | **Details**                                                                         | **Countermeasures**                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| **Threat**          | Ransomware encrypts all critical data, potentially crippling business operations.   | –                                                                                                       |
| **Likelihood**      | Medium to high                                                                      | –                                                                                                       |
| **Impact**          | Very high – affects business continuity, data integrity, and can lead to data loss. | –                                                                                                       |
| **Countermeasures** | –                                                                                   | • Regular, secure backups  <br>• Timely patch management  <br>• Employee training on phishing detection |

---

#### OWASP Vulnerability Research (XSS)

| **Vulnerability**     | **OWASP Top Ten Category**                      | **CWE Numbers**                     |
| --------------------- | ----------------------------------------------- | ----------------------------------- |
| Cross-Site Scripting  | Injection flaws / Historically its own category | CWE-79 (primary), CWE-116 (related) |

---

# HZ 2

#### How SQL Injection Works

|**Aspect**|**Description**|
|---|---|
|Vulnerability|Unsanitized user input is directly concatenated into SQL queries, allowing attackers to modify them.|
|Impact|An attacker can alter the query to bypass authentication, extract, or even modify data.|

---
#### Exploitation Example in the Insecure App

| **Exploit Scenario** | **Input Example**                                               | **Outcome**                                                                                                                      |
| -------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Bypass Login         | Username: `administrator'--`  <br>Password: any non-empty value | The injected comment (`--`) ends the query early, letting an attacker log in as administrator without knowing the real password. |

---
#### New Code Fixing SQLInjection
```cs
public ActionResult<User> Login(LoginDto request)
{
    if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
    {
        return BadRequest();
    }

    string hashedPassword = MD5Helper.ComputeMD5Hash(request.Password);

    // Use parameterized query with FromSqlInterpolated to prevent SQL injection.
    User? user = _context.Users
        .FromSqlInterpolated($"SELECT * FROM Users WHERE username = {request.Username} AND password = {hashedPassword}")
        .FirstOrDefault();

    if (user == null)
    {
        return Unauthorized("login failed");
    }

    return Ok(user);
}
```

# HZ 3

#### Old Login Insecurity & Exploitation

| **Issue**                    | **Explanation**                                                                                                                               | **Exploitation Example**                           |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Insecure Login without Token | The old login only checked credentials using SQL (even after fixing SQL Injection) and did not enforce any session or token-based protection. | An attacker can call protected endpoints directly. |
| Broken Access Control        | No authorization is enforced on endpoints; anyone can access news or update content without being properly authenticated.                     | Direct API calls without logging in are allowed.   |

----
#### JWT Structure & Security

| **Component**    | **Content/Example**                                                                           | **Why It’s Secure**                                                                   |
| ---------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Header           | `{ "alg": "HS512", "typ": "JWT" }`                                                            | Specifies the algorithm and type; any change in header will invalidate the signature. |
| Payload (Claims) | `{"jti": "<uuid>", "nameid": "<user id>", "unique_name": "<username>", "role": "admin/user"}` | Contains user data; any tampering will cause signature mismatch.                      |
| Signature        | HMAC SHA512 of header and payload using a secret key from configuration                       | Ensures token integrity—if modified, the signature check fails.                       |

---
#### Backend – Login Endpoint with JWT Creation (LoginController.cs):

```cs
using M183.Controllers.Dto;
using M183.Controllers.Helper;
using M183.Data;
using M183.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly NewsAppContext _context;
        private readonly IConfiguration _configuration;

        public LoginController(NewsAppContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        /// <summary>
        /// Authenticates a user and returns a JWT token upon successful login.
        /// </summary>
        [HttpPost]
        public ActionResult<string> Login(LoginDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest();
            }

            string hashedPassword = MD5Helper.ComputeMD5Hash(request.Password);

            // Use parameterized query to prevent SQL injection.
            User? user = _context.Users
                .FromSqlInterpolated($"SELECT * FROM Users WHERE username = {request.Username} AND password = {hashedPassword}")
                .FirstOrDefault();

            if (user == null)
            {
                return Unauthorized("login failed");
            }

            // Create JWT
            var key = new SymmetricSecurityKey(Convert.FromBase64String(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                new Claim(ClaimTypes.Role, user.IsAdmin ? "admin" : "user")
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(12),
                signingCredentials: creds
            );

            string jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return Ok(jwt);
        }
    }
}
```
**Explanation:**

- **Input Validation:**  
    The code first checks that the login request and its properties are not null or empty.
    
- **Credential Verification:**  
    It computes the MD5 hash of the entered password and uses a parameterized SQL query to prevent SQL injection when checking the user credentials.
    
- **JWT Creation:**  
    When a valid user is found, a symmetric key is obtained from the configuration. The token is signed using HMAC SHA512.  
    Claims are added, including a unique token ID (`jti`), the user's ID (`NameId`), username (`unique_name`), and the user's role (either "admin" or "user").
    
- **Token Generation:**  
    A JWT is created with the specified issuer, audience, claims, and a 12-hour expiration, then returned to the client as a plain text response.
    

---

#### Backend – JWT Middleware Configuration (Program.cs)
```cs
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Configure services (e.g., DbContext, Controllers, Swagger, etc.)
builder.Services.AddDbContext<NewsAppContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("SongContext")));
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
         options.TokenValidationParameters = new TokenValidationParameters
         {
             ValidateIssuer = true,
             ValidateAudience = true,
             ValidateLifetime = true,
             ValidateIssuerSigningKey = true,
             ValidIssuer = builder.Configuration["Jwt:Issuer"],
             ValidAudience = builder.Configuration["Jwt:Audience"],
             IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(builder.Configuration["Jwt:Key"]))
         };
    });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Use Authentication and Authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

```
**Explanation:**

- **Service Configuration:**  
    The code registers the required services like DbContext, controllers, and Swagger.
    
- **JWT Authentication Setup:**  
    The authentication service is configured to use the JWT Bearer scheme.  
    Token validation parameters are set up to ensure that the issuer, audience, lifetime, and signing key (read from the configuration) are all validated.
    
- **Middleware Integration:**  
    The `UseAuthentication()` and `UseAuthorization()` middleware are added before mapping the controllers so that protected endpoints require a valid JWT.
---
#### Frontend – Login and Token Storage (login.js)
```cs
function onLogin() {
    var inputUsername = document.getElementById("username");
    var inputPassword = document.getElementById("password");

    fetch("/api/Login", {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ Username: inputUsername.value, Password: inputPassword.value })
    })
        .then((response) => {
            if (response.ok) {
                return response.json();
            }
            else {
                throw new Error(response.statusText + " (" + response.status + ")");
            }
        })
        .then((data) => {
            // Store JWT token
            saveUser(data);
            window.location.href = "index.html";
        })
        .catch((error) => {
            var labelResult = document.getElementById("labelResult");
            labelResult.innerText = error;
            labelResult.classList.remove("hidden");
        });
}
```
**Explanation:**

- **Login Request:**  
    Reads the username and password from the input fields and sends them as a JSON payload in a POST request to `/api/Login`.
    
- **Token Retrieval and Storage:**  
    If the response is successful (`response.ok`), parses the JSON (which contains the JWT), calls `saveUser(data)` to store the user info and token, then redirects to `index.html`.
    
- **Error Handling:**  
    If the response fails or another error occurs, catches the error, sets the `labelResult` element’s text to the error message, and makes it visible by removing its `"hidden"` class.

----
#### Frontend - News loading
```cs
function loadNews() {
    const user = JSON.parse(localStorage.getItem(userKey));

    fetch("/api/News", {
        method: "GET",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${user.token}`
        }
    })
```
**Explanation:**

- **User Retrieval:**  
    The function reads the serialized user object from `localStorage` using `userKey`, then parses it into a JavaScript object so you can access the stored JWT token via `user.token`.
    
- **News Fetch Request:**  
    It invokes `fetch("/api/News", { method: "GET", … })` to send a GET request to the `/api/News` endpoint and retrieve the latest news items.
    
- **Headers Configuration:**  
    Three headers are set on the request:
    
    - `Accept: application/json` tells the server that the client expects a JSON response.
        
    - `Content-Type: application/json` declares that any request body is in JSON format (though GET requests usually omit a body).
        
    - `Authorization: Bearer ${user.token}` includes the JWT in a Bearer token scheme so that the server can authenticate and authorize the request.

**This was also added to:**

- **handleDelete**
- **handleSave**
- **handleSaveNew**
- **onPasswordChange**
---
#### Backend `[Authorize]`

**NewsController**
```cs
[Route("api/[controller]")]

[ApiController]

[Authorize]

public class NewsController : ControllerBase

{

private readonly TimeZoneInfo tzi = TimeZoneInfo.FindSystemTimeZoneById("Central Europe Standard Time");

private readonly NewsAppContext _context;

  

public NewsController(NewsAppContext context)

{

_context = context;

}

  

private News SetTimezone(News news)

{

news.PostedDate = TimeZoneInfo.ConvertTimeFromUtc(news.PostedDate, tzi);

return news;

}
```

**UserController**
```cs
[HttpPatch("password-update")]

[Authorize]

[ProducesResponseType(200)]

[ProducesResponseType(400)]

[ProducesResponseType(404)]

public ActionResult PasswordUpdate(PasswordUpdateDto request)
```
**Explanation:**

The `[Authorize]` tag checks if the Token in the Header is correct and authorizes access with it.
The Token is stored in **localStorage** in the browser, looking like this
`Storage { loggedInUser: '{"id":1,"username":"administrator","isAdmin":true,"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6ImFkbWluaXN0cmF0b3IiLCJuYW1laWQiOiIxIiwicm9sZSI6IkFkbWluIiwibmJmIjoxNzQ2MjY5MDA1LCJleHAiOjE3NDYyNzI2MDUsImlhdCI6MTc0NjI2OTAwNX0.AJXnIF-TRoXJuZwUn5R7g0JPGUNtjHqRbshBlVHL9V8"}', length: 1 }`

----
#### Authentication

#### TOTP Explanation:

| Phase                      | Client-side Action                                                                       | Server-side Action                                                                     | Technical Details                                                                                                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Provisioning**        | • Scan the QR code into your authenticator app• Secret is stored on your device          | • Generate a random secret key• Encode it as a QR code for easy transfer               | The secret is a random value (e.g. 160 bits, Base32-encoded). QR-code avoids typo-prone manual entry                                                                                                |
| **2. Code Generation**     | • Every 30 seconds, compute a one-time code using the stored secret and the current time | —                                                                                      | The app applies an HMAC (commonly SHA-1) to the time-step counter and secret, then truncates to a 6-digit number. Codes rotate automatically (typically every 30 s)                                 |
| **3. Authentication**      | • Log in with username + password• Enter the current 6-digit TOTP code                   | • Verify password• Recompute expected TOTP for current (±1 interval) and compare       | Server allows a small time-step window (e.g. ±30 s) to accommodate clock drift. Both factors (“something you know” and “something you have”) must match to grant access.                            |
| **4. Recovery & Security** | • Keep backup (recovery) codes in a safe place• Protect your device’s secret             | • Offer one-time static backup codes when TOTP app is unavailable• Rate-limit attempts | If you lose your phone or it’s stolen, recovery codes let you regain access. If an attacker steals the secret (from server or device), they can generate valid codes—so secure storage is critical. |

---
### Two-Factor Authentication (TOTP) Implementation

This part outlines the key changes made to implement Time-based One-Time Password  Two-Factor Authentication  using the `GoogleAuthenticator` library.

#### Backend – User Model Update 

```cs
using System.ComponentModel.DataAnnotations;

namespace M183.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty; // Initialize string properties
        public string Password { get; set; } = string.Empty; // Initialize string properties
        public bool IsAdmin { get; set; }

        // Add these properties for 2FA
        public string? TwoFactorSecret { get; set; } // Nullable string to store the secret
        public bool IsTwoFactorEnabled { get; set; } = false; // Flag to check if 2FA is active
    }
}
```
**Explanation:**

- **TwoFactorSecret:** A nullable string property was added to store the unique secret key for each user, used for generating TOTP codes. It's nullable because users might not have 2FA enabled.
- **IsTwoFactorEnabled:** A boolean flag was added to indicate whether the user has successfully verified and enabled 2FA on their account. Defaults to `false`.
---
#### Backend – Database Migration
```cs
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace M183.Migrations
{
    /// <inheritdoc />
    public partial class AddTwoFactorAuthToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsTwoFactorEnabled",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "TwoFactorSecret",
                table: "Users",
                type: "nvarchar(max)",
                nullable: true);

            // Update existing seed data to include default values for new columns
            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "IsTwoFactorEnabled", "TwoFactorSecret" },
                values: new object[] { false, null });

            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "IsTwoFactorEnabled", "TwoFactorSecret" },
                values: new object[] { false, null });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsTwoFactorEnabled",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TwoFactorSecret",
                table: "Users");
        }
    }
}
```
**Explanation:**

- **Up Method:** Defines the changes to apply to the database schema. It adds the `IsTwoFactorEnabled` (boolean, non-nullable, default `false`) and `TwoFactorSecret` (string, nullable) columns to the `Users` table. It also updates the existing seeded user data to set default values for these new columns.
    
- **Down Method:** Defines how to revert the changes made by the `Up` method, primarily by dropping the added columns.
---
#### Backend – Activation: Secret/QR Code Generation
```cs
[Authorize] // Require user to be logged in

public class TwoFactorAuthController : ControllerBase

{

private readonly NewsAppContext _context;

private const string Issuer = "InsecureApp"; // App name shown in authenticator

  

public TwoFactorAuthController(NewsAppContext context, IConfiguration configuration) { /*...*/ }

  

[HttpGet("setup")]

public async Task<ActionResult<TwoFactorSetupDto>> GetSetupInfo()

{

var userId = GetCurrentUserId(); // Helper to get ID from JWT

if (userId == null) return Unauthorized();

  

var user = await _context.Users.FindAsync(userId.Value);

if (user == null) return NotFound("User not found.");

  

// Generate and save a new secret if needed

if (string.IsNullOrEmpty(user.TwoFactorSecret) || !user.IsTwoFactorEnabled)

{

user.TwoFactorSecret = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);

await _context.SaveChangesAsync();

}

  

// Generate QR Code setup info using GoogleAuthenticator

var tfa = new TwoFactorAuthenticator();

var setupInfo = tfa.GenerateSetupCode(Issuer, user.Username, user.TwoFactorSecret, false);

  

return Ok(new TwoFactorSetupDto

{

ManualEntryKey = setupInfo.ManualEntryKey,

QrCodeImageUrl = setupInfo.QrCodeSetupImageUrl // Data URI for the QR code image

});

}

  

[HttpPost("verify")]

public async Task<IActionResult> VerifyAndEnable([FromBody] TwoFactorVerifyDto request)

{

var userId = GetCurrentUserId();

if (userId == null) return Unauthorized();

var user = await _context.Users.FindAsync(userId.Value);

// ... (Error handling for user not found, secret not set) ...

  

var tfa = new TwoFactorAuthenticator();

bool isValid = tfa.ValidateTwoFactorPIN(user.TwoFactorSecret!, request.Code); // Validate code

  

if (isValid)

{

user.IsTwoFactorEnabled = true; // Enable 2FA for the user

await _context.SaveChangesAsync();

return Ok("Two-Factor Authentication enabled successfully.");

}

  

return BadRequest("Invalid code.");

}

  

private int? GetCurrentUserId() { /* ... gets user ID from ClaimsPrincipal ... */ }

}
```
**Explanation:**

- **GetSetupInfo Endpoint (GET /api/TwoFactorAuth/setup):**  
    Requires authentication (`[Authorize]`). Retrieves the logged-in user. Generates a new 10-character secret key and saves it to the user's record if one doesn't exist or if 2FA isn't already enabled. Uses `GoogleAuthenticator.GenerateSetupCode` to create the necessary data for an authenticator app, including the `ManualEntryKey` (the secret) and a `QrCodeSetupImageUrl` (a data URI representing the QR code image). Returns this information to the frontend.
    
- **VerifyAndEnable Endpoint (POST /api/TwoFactorAuth/verify):**  
    Requires authentication. Retrieves the user and their stored secret. Uses `GoogleAuthenticator.ValidateTwoFactorPIN` to check if the `Code` provided by the user matches the expected code generated from the secret. If valid, sets the user's `IsTwoFactorEnabled` flag to `true` in the database. Returns success or failure status.
---
#### Backend – Login: 2FA Check
```cs
public class LoginController : ControllerBase
{
    // ... Constructor ...

    [HttpPost]
    public async Task<ActionResult<LoginResponseDto>> Login(LoginDto request)
    {
        // ... (Validate request, hash password) ...

        User? user = await _context.Users
            .Where(u => u.Username == request.Username && u.Password == hashedPassword)
            .FirstOrDefaultAsync();

        if (user == null) return Unauthorized("Invalid credentials.");

        // Check if 2FA is enabled for this user
        if (user.IsTwoFactorEnabled)
        {
            // Return response indicating 2FA is required, include UserId for next step
            return Ok(new LoginResponseDto { RequiresTwoFactor = true, UserId = user.Id });
        }

        // 2FA not enabled, generate JWT token immediately
        var token = GenerateJwtToken(user);
        return Ok(new LoginResponseDto { /* ... user info + token ... */ });
    }

    [HttpPost("verify-2fa")]
    public async Task<ActionResult<LoginResponseDto>> VerifyTwoFactor(TwoFactorLoginDto request)
    {
        if (request == null || string.IsNullOrEmpty(request.Code) || request.UserId <= 0)
            return BadRequest("User ID and code are required.");

        var user = await _context.Users.FindAsync(request.UserId);
        // ... (Error handling for user not found, 2FA not enabled) ...

        if (string.IsNullOrEmpty(user.TwoFactorSecret))
            return BadRequest("2FA setup not initiated."); // Should not happen if IsTwoFactorEnabled is true

        var tfa = new TwoFactorAuthenticator();
        bool isValid = tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, request.Code); // Validate code

        if (isValid)
        {
            // Code is valid, generate JWT token and return user info
            var token = GenerateJwtToken(user);
            return Ok(new LoginResponseDto { /* ... user info + token ... */ });
        }

        return BadRequest("Invalid 2FA code.");
    }

    private string GenerateJwtToken(User user) { /* ... JWT generation logic ... */ }
}

// DTOs used by the controller
public class LoginResponseDto { /* ... properties: RequiresTwoFactor, UserId, Token, etc. ... */ }
public class TwoFactorLoginDto { public int UserId { get; set; } public string Code { get; set; } }
```
**Explanation:**

- **Login Endpoint (POST /api/Login):**  
    After successfully verifying the username and password, it checks the user's `IsTwoFactorEnabled` flag.
    
    - If `true`, it returns a `LoginResponseDto` with `RequiresTwoFactor = true` and the `UserId`, without generating a JWT token yet.
        
    - If `false`, it proceeds directly to generate and return the JWT token and user info as before.
        
- **VerifyTwoFactor Endpoint (POST /api/Login/verify-2fa):**  
    This new endpoint is called by the frontend when the initial login requires 2FA. It receives the `UserId` (from the initial login response) and the `Code` entered by the user. It retrieves the user and their `TwoFactorSecret`, then uses `GoogleAuthenticator.ValidateTwoFactorPIN` to validate the code.
    
    - If valid, it generates the JWT token and returns it along with user info in the `LoginResponseDto`.
        
    - If invalid, it returns a `BadRequest`.
---
#### Frontend – Activation Page

```js
// Function called by index.html when page=activate2fa
function createActivate2faForm() {
    var main = document.getElementById("main");
    main.innerHTML = ''; // Clear content

    // Dynamically create HTML elements for title, QR code image, manual key,
    // verification code input, and verify button.
    // Example snippet for QR code image and manual key display:
    setupDiv.innerHTML = `
        <p>Scan the QR code below...</p>
        <div id="qr-code-container">
            <img id="qr-code-image" src="" alt="QR Code Loading..." />
        </div>
        <p>...manually enter this key:</p>
        <p><strong id="manual-entry-key">Loading...</strong></p>
    `;
    // Example snippet for verification form:
    verifyDiv.innerHTML = `
        <p>Enter the code from your authenticator app...</p>
        <form id="verify-form" action="javascript:verifyCode()">
            <input type="text" id="tfa-code" ... />
            <button type="submit">Verify and Enable</button>
        </form>
        <div id="error-message" class="warning hidden"></div>
    `;
    main.appendChild(setupDiv);
    main.appendChild(verifyDiv);

    // Fetch setup info from backend after creating the form
    loadSetupInfo();
}

async function loadSetupInfo() {
    const user = getUserData(); // Get logged-in user data (including token)
    // ... (Handle not logged in) ...

    // Fetch QR code URL and manual key from backend API
    const response = await fetch('/api/TwoFactorAuth/setup', {
        headers: { 'Authorization': `Bearer ${user.token}` /* ... */ }
    });

    if (response.ok) {
        const data = await response.json();
        // Update the src of the img tag and the text of the strong tag
        document.getElementById('qr-code-image').src = data.qrCodeImageUrl;
        document.getElementById('manual-entry-key').textContent = data.manualEntryKey;
    } else { /* Handle error */ }
}

async function verifyCode() {
    const code = document.getElementById('tfa-code').value;
    const user = getUserData();
    // ... (Handle missing code or user) ...

    // Send the entered code to the backend API for verification
    const response = await fetch('/api/TwoFactorAuth/verify', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${user.token}`, /* ... */ },
        body: JSON.stringify({ code: code })
    });

    if (response.ok) {
        toastr.success('Two-Factor Authentication enabled successfully!');
        // Redirect after success
        setTimeout(() => { window.location.href = 'index.html'; }, 2000);
    } else { /* Handle error, show message */ }
}
```
```html
<!-- ... (head includes activate-2fa.js) ... -->
<nav>
    <ul>
        <!-- ... other links ... -->
        <li><a href="index.html?page=activate2fa">Setup 2FA</a></li> <!-- Link added -->
    </ul>
</nav>
<!-- ... -->
<script>
    // ... (script logic) ...
    if (isLoggedIn()) {
        // ... (setup user dropdown) ...
        switch (page) {
            // ... other cases ...
            case 'activate2fa':
                createActivate2faForm(); // Call function to build the page
                break;
            default:
                loadNews();
                break;
        }
    }
    // ...
</script>
```
**Explanation:**

- **Navigation:** A link to `index.html?page=activate2fa` is added in `index.html`.
    
- **Routing (index.html script):** When the `page` parameter is `activate2fa`, the script calls `createActivate2faForm()` from `activate-2fa.js`.
    
- **Form Creation (`createActivate2faForm`):** Dynamically generates the HTML structure for the activation page within the `<main>` element, including placeholders for the QR code, manual key, and verification code input form. It then calls `loadSetupInfo`.
    
- **Loading Setup Info (`loadSetupInfo`):** Fetches the `QrCodeImageUrl` and `ManualEntryKey` from the `/api/TwoFactorAuth/setup` backend endpoint (using the user's JWT) and populates the corresponding HTML elements.
    
- **Verifying Code (`verifyCode`):** Called when the verification form is submitted. It sends the code entered by the user to the `/api/TwoFactorAuth/verify` backend endpoint. On success, it shows a confirmation and redirects the user.
---
#### Frontend – 2FA Input During Login
```js
let pendingUserId = null; // Store UserId if 2FA is needed

function createLoginForm() {
    // ... (create username/password divs) ...

    /* 2FA Code Input (Initially Hidden) */
    var divTwoFactor = document.createElement("div");
    divTwoFactor.id = "divTwoFactor";
    divTwoFactor.style.display = 'none'; // Hide initially
    divTwoFactor.innerHTML = `
        <br><label for="tfa-code">Verification Code</label><br>
        <input type="text" id="tfa-code" autocomplete="off" inputMode="numeric" pattern="[0-9]{6}" maxlength="6">
    `;

    // ... (create result/button divs) ...

    var loginForm = document.createElement("form");
    loginForm.id = "loginForm";
    loginForm.onsubmit = function() { onLogin(); return false; }; // Initial submit calls onLogin
    // ... (append divs to form) ...
    loginForm.appendChild(divTwoFactor); // Add the hidden 2FA div
    // ... (append form to main) ...
}

function onLogin() {
    // ... (fetch /api/Login with username/password) ...
    .then((data) => {
        if (data.requiresTwoFactor) {
            // Backend indicated 2FA is needed
            pendingUserId = data.userId; // Store the UserId from response
            showTwoFactorInput();        // Modify form to show 2FA input
        } else {
            // Login successful (no 2FA or already verified)
            saveUser(data); // Store user data and token
            window.location.href = "index.html";
        }
    })
    // ... (catch errors) ...
}

function showTwoFactorInput() {
    // Hide username/password fields
    document.getElementById("divUsername").style.display = 'none';
    document.getElementById("divPassword").style.display = 'none';
    // Show the 2FA input field
    document.getElementById("divTwoFactor").style.display = 'block';
    // Change button text and form's submit action
    document.getElementById("loginButton").value = 'Verify Code';
    document.getElementById("loginForm").onsubmit = function() { onVerify2FA(); return false; };
    document.getElementById("tfa-code").focus(); // Focus the code input
}

function onVerify2FA() {
    const code = document.getElementById("tfa-code").value;
    // ... (validate code input, check pendingUserId) ...

    // Send UserId and Code to the verification endpoint
    fetch("/api/Login/verify-2fa", {
        method: "POST",
        headers: { /* ... */ },
        body: JSON.stringify({ UserId: pendingUserId, Code: code })
    })
    .then(response => response.ok ? response.json() : Promise.reject(response))
    .then((data) => {
        // 2FA verification successful
        saveUser(data); // Store user data and token from response
        window.location.href = "index.html";
    })
    .catch((error) => { /* Handle verification error */ });
}
```
**Explanation:**

- **Form Structure (`createLoginForm`):** The login form now includes a `div` (`divTwoFactor`) containing the label and input field for the 2FA code. This `div` is initially hidden (`style.display = 'none'`).
    
- **Initial Login Check (`onLogin`):** When the initial login API call (`/api/Login`) returns successfully, the code checks the `requiresTwoFactor` flag in the response data.
    
    - If `true`, it stores the returned `userId` into the `pendingUserId` variable and calls `showTwoFactorInput()`.
        
    - If `false`, it proceeds with saving the user/token and redirecting as normal.
        
- **Showing 2FA Input (`showTwoFactorInput`):** This function hides the username and password input fields, makes the `divTwoFactor` visible, changes the text of the submit button to "Verify Code", and changes the form's `onsubmit` handler to call `onVerify2FA()` instead of `onLogin()`.
    
- **Verifying 2FA Code (`onVerify2FA`):** This function is called when the user submits the 2FA code. It reads the code from the input field, retrieves the stored `pendingUserId`, and sends both to the `/api/Login/verify-2fa` backend endpoint. If successful, it receives the final user data/token, saves it using `saveUser()`, and redirects to the main page.
---
# HZ4
#### Why should you require to ask for the current password?

- **Confirm it’s really you**  
    By asking for your old password, the system makes sure the person changing the password already knows it.
    
- **Block hijackers**  
    Even if someone steals your login session, they can’t swap in a new password without the old one.
    
- **Stop automated abuse**  
    Bots trying to force-reset passwords will fail if they don’t know what you already have.

### Implementation of current password
#### Backend – DTO Update
```cs
namespace M183.Controllers.Dto

{

public class PasswordUpdateDto

{

public int UserId { get; set; }

public string CurrentPassword { get; set; } = string.Empty; // Added this line

public string NewPassword { get; set; } = string.Empty;

// public bool IsAdmin { get; set; } // This might be unnecessary here

}

}
```
**Explanation:**

- **CurrentPassword Property:** A new string property `CurrentPassword` was added to the `PasswordUpdateDto`. This allows the frontend to send the user's currently entered password along with the new password to the backend API endpoint.
---
#### Backend – Controller Logic Update
```cs
// ... (using statements and class definition) ...

        [HttpPatch("password-update")]
        [Authorize]
        // ... (ProducesResponseType attributes) ...
        public ActionResult PasswordUpdate(PasswordUpdateDto request)
        {
            // --- Basic Request Validation ---
            if (request == null || string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrEmpty(request.NewPassword))
                return BadRequest("Current and new passwords are required."); // Check if CurrentPassword is provided

            // --- Authorization and User Retrieval ---
            var currentUserIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!int.TryParse(currentUserIdClaim, out int currentUserId) || currentUserId != request.UserId)
                return Unauthorized("User ID mismatch or invalid token.");

            var user = _context.Users.Find(request.UserId);
            if (user == null) return NotFound($"User {request.UserId} not found");

            // --- Current Password Verification ---
            string hashedCurrentPassword = MD5Helper.ComputeMD5Hash(request.CurrentPassword); // Hash the provided current password
            if (user.Password != hashedCurrentPassword) // Compare with the stored hash
            {
                 return BadRequest("Incorrect current password."); // Return error if it doesn't match
            }
            // --- End Current Password Verification ---

            // --- New Password Rules Validation ---
            // ... (validation logic for new password rules) ...
            // --- End New Password Rules Validation ---

            // --- Final Check: New vs Current Password ---
            string hashedNewPassword = MD5Helper.ComputeMD5Hash(request.NewPassword);
            if (user.Password == hashedNewPassword)
            {
                return BadRequest("New password cannot be the same as the current password.");
            }

            // --- Update Password ---
            user.Password = hashedNewPassword;
            _context.Users.Update(user);
            _context.SaveChanges();

            return Ok("Password updated successfully.");
        }
// ... (Helper functions like CalculateRomanValue) ...
```
**Explanation:**

- **Input Validation:** The controller action now checks if `request.CurrentPassword` is null or empty.
    
- **Password Hashing & Comparison:** Before proceeding with rule validation or updating the password, the controller hashes the `CurrentPassword` received from the request using the same `MD5Helper.ComputeMD5Hash` method used elsewhere.
    
- **Verification:** This generated hash is compared against the `user.Password` hash stored in the database.
    
- **Error Handling:** If the hashes do not match, a `BadRequest` (HTTP 400) response is returned with the message `"Incorrect current password."`, preventing the password change.
---
#### Frontend – Form Creation
```js
function createChangePasswordForm() {
    // ... (Title and Rules Display Area setup) ...

    /* Current Password. */
    var labelCurrentPassword = document.createElement('label');
    labelCurrentPassword.innerText = 'Current password';
    var inputCurrentPassword = document.createElement('input');
    inputCurrentPassword.id = 'currentPassword'; // Assign ID
    inputCurrentPassword.type = 'password';
    inputCurrentPassword.autocomplete = 'current-password'; // Help password managers
    var divCurrentPassword = document.createElement('div');
    divCurrentPassword.appendChild(labelCurrentPassword);
    divCurrentPassword.innerHTML += '<br>';
    divCurrentPassword.appendChild(inputCurrentPassword);
    // --- End Current Password ---

    /* New Password. */
    // ... (New Password input setup) ...

    /* Confirm New Password. */
    // ... (Confirm New Password input setup) ...

    /* Show Password Checkbox */
    // ... (Show Password checkbox setup) ...

    /* Change button. */
    // ... (Submit button setup) ...

    /* Form. */
    var changePasswordForm = document.createElement('form');
    changePasswordForm.action = 'javascript:onPasswordChange()';
    changePasswordForm.appendChild(divCurrentPassword); // Add the current password field div
    changePasswordForm.appendChild(divPassword);
    changePasswordForm.appendChild(divConfirmPassword);
    changePasswordForm.appendChild(divShowPassword);
    changePasswordForm.appendChild(divButton);

    main.appendChild(changePasswordForm);
    inputCurrentPassword.focus(); // Focus current password field first

    // ... (Initial call to updatePasswordRulesDisplay) ...
}
```
**Explanation:**

- **Input Field Added:** A new `div` (`divCurrentPassword`) containing a label and an input field (`type="password"`, `id="currentPassword"`) was created dynamically.
    
- **Added to Form:** This `divCurrentPassword` is appended to the `changePasswordForm` element before the "New Password" field, making it part of the submitted form data (handled via JavaScript).
---
#### Frontend – Form Submission

```js
function onPasswordChange() {
    var inputCurrentPassword = document.getElementById('currentPassword'); // Get the current password input
    var inputPassword = document.getElementById('password');
    var inputConfirmPassword = document.getElementById('confirmPassword');
    const newPassword = inputPassword.value;

    // --- Basic Input Checks ---
    if (!inputCurrentPassword.value) { // Check if current password field is empty
        toastr.warning('Current Password cannot be empty', 'Warning'); return;
    }
    // ... (other basic checks: new password empty, passwords match, new vs current) ...

    // --- Final Password Rules Validation ---
    // ... (validation logic for new password rules) ...
    // --- End Final Password Rules Validation ---

    const user = getUserData();
    if (!user || !user.token) {
        toastr.error('You must be logged in to change your password.', 'Error');
        return;
    }

    // --- Fetch call ---
    fetch('/api/User/password-update', {
        method: 'PATCH',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${user.token}`
        },
        body: JSON.stringify({
            UserId: user.id,
            CurrentPassword: inputCurrentPassword.value, // Include current password value in the request body
            NewPassword: newPassword,
        })
    })
    // ... (fetch .then and .catch logic) ...
}
```
**Explanation:**

- **Get Input Value:** Inside `onPasswordChange`, the value from the `#currentPassword` input field is retrieved using `document.getElementById('currentPassword').value`.
    
- **Client-Side Check:** A basic check is added to ensure the "Current Password" field is not submitted empty.
    
- **Include in Request:** The retrieved `inputCurrentPassword.value` is included in the JSON payload sent in the body of the `fetch` request to the `/api/User/password-update` endpoint, matching the `CurrentPassword` property expected by the backend DTO.
---
### Implementation of password rules

#### Frontend – Defining and Displaying Rules 

````javascript
// --- Password Rule Definitions ---
const passwordRules = [
    { id: 'rule-length', text: 'Minimum 8 characters long', validate: (pw) => pw.length >= 8 },
    { id: 'rule-uppercase', text: 'At least one uppercase letter (A-Z)', validate: (pw) => /[A-Z]/.test(pw) },
    { id: 'rule-number', text: 'At least one number (0-9)', validate: (pw) => /[0-9]/.test(pw) },
    { id: 'rule-special', text: 'At least one special character (e.g., !@#$%^&*)', validate: (pw) => /[!@#$%^&*()\-_=+[\]{}|;:'",.<>/?~]/.test(pw) },
    { id: 'rule-fruit', text: 'Must contain a fruit name (case-insensitive): apple, banana, orange, grape, or pear', validate: (pw) => ["apple", "banana", "orange", "grape", "pear"].some(fruit => pw.toLowerCase().includes(fruit)) },
    {
        id: 'rule-roman-count', text: 'Must contain at least two separate sequences of uppercase Roman numerals (I, V, X, L, C, D, M)', validate: (pw) => {
            const romanMatches = pw.match(/[IVXLCDM]+/g);
            return romanMatches ? romanMatches.length >= 2 : false;
        }
    },
    {
        id: 'rule-roman-sum', text: 'The total calculated value of all Roman numeral sequences must sum up to exactly 69', validate: (pw) => {
            const romanMatches = pw.match(/[IVXLCDM]+/g);
            if (!romanMatches || romanMatches.length < 2) return false; // Depends on previous rule
            let totalRomanValue = 0;
            romanMatches.forEach(match => {
                totalRomanValue += calculateRomanValue(match); // Uses helper function
            });
            return totalRomanValue === 69;
        }
    }
];
// --- End Password Rule Definitions ---

// ...

function createChangePasswordForm() {
    // ... (Title setup) ...

    // --- Add Password Rules Display Area ---
    var rulesDiv = document.createElement('div');
    rulesDiv.style.marginBottom = '1.5em';
    rulesDiv.style.padding = '1em';
    rulesDiv.style.border = '1px solid #ccc';
    rulesDiv.style.borderRadius = '5px';
    rulesDiv.innerHTML = `<h4>New Password Requirements:</h4><ul id="password-rules-list"></ul>`; // Add ul with id
    main.appendChild(rulesDiv);

    // Populate the rules list (initially hidden except the first)
    const rulesListElement = document.getElementById('password-rules-list');
    if (rulesListElement) {
        passwordRules.forEach((rule, index) => {
            const li = document.createElement('li');
            li.id = rule.id; // Assign ID for later reference
            li.textContent = rule.text; // Set the rule text
            li.style.display = 'none'; // Hide all initially
            rulesListElement.appendChild(li);
        });
        // Show the first rule initially
        const firstRuleElement = document.getElementById(passwordRules[0].id);
         if (firstRuleElement) {
             firstRuleElement.style.display = 'list-item'; // Make first rule visible
             firstRuleElement.style.color = 'red'; // Start as unmet (red)
         }
    }
    // --- End Password Rules Display Area ---

    // ... (Rest of the form creation: Current Pw, New Pw, Confirm Pw, Checkbox, Button) ...
}
````

**Explanation:**

*   **`passwordRules` Array:** An array named `passwordRules` is defined globally in the script. Each object in the array represents a rule and contains:
    *   `id`: A unique ID used to target the corresponding `<li>` element.
    *   `text`: The user-facing description of the rule.
    *   `validate`: A function that takes the password string and returns `true` if the rule is met, `false` otherwise.
*   **Dynamic List Creation:** The `createChangePasswordForm` function creates a `div` to contain the rules and an unordered list (`<ul>`) with the ID `password-rules-list`.
*   **Populating the List:** It iterates through the `passwordRules` array. For each rule, it creates a list item (`<li>`), sets its `id` and `textContent` based on the rule object, and initially hides it using `style.display = 'none'`.
*   **Initial State:** After creating all list items, it specifically finds the first rule's `<li>` element and makes it visible (`style.display = 'list-item'`), coloring it red to indicate it's the first requirement to be met.

#### Frontend – Dynamic Validation Logic

````javascript
// ... (passwordRules array definition) ...

// --- Function to Update Rule Display ---
function updatePasswordRulesDisplay() {
    const passwordInput = document.getElementById('password');
    const rulesList = document.getElementById('password-rules-list');
    if (!passwordInput || !rulesList) return;

    const newPassword = passwordInput.value;
    let allPreviousMet = true; // Flag to track if preceding rules are met

    passwordRules.forEach((rule, index) => {
        const ruleElement = document.getElementById(rule.id);
        if (!ruleElement) return;

        // Check if the current rule is met AND all previous rules were met
        const currentRuleMet = allPreviousMet && rule.validate(newPassword);

        if (currentRuleMet) {
            // Rule met: Show it and color it green
            ruleElement.style.display = 'list-item';
            ruleElement.style.color = 'green';
        } else {
            // Rule not met OR a previous rule failed:

            // Hide this rule and all subsequent rules
            for (let j = index; j < passwordRules.length; j++) {
                const subsequentRuleElement = document.getElementById(passwordRules[j].id);
                if (subsequentRuleElement) {
                    subsequentRuleElement.style.display = 'none';
                }
            }
            // If this is the *first* rule that failed (all previous were met), show it in red
            if (allPreviousMet) {
                 ruleElement.style.display = 'list-item';
                 ruleElement.style.color = 'red';
            }

            allPreviousMet = false; // Mark that subsequent rules depend on this one failing
        }
    });
}
// --- End Function to Update Rule Display ---

// ...

function createChangePasswordForm() {
    // ... (Form setup) ...

    /* New Password. */
    // ... (Label and input creation) ...
    inputPassword.id = 'password';
    inputPassword.type = 'password';
    // Add event listener to update rules display on input
    inputPassword.addEventListener('input', updatePasswordRulesDisplay); // Trigger validation on typing
    // ... (Add input to div) ...

    // ... (Rest of form setup) ...

    // Initial call to set the state based on empty input
    updatePasswordRulesDisplay();
}

// ...

function onPasswordChange() {
    // ... (Basic input checks) ...

    // --- Final Password Rules Validation (Client-side before sending) ---
    let validationError = null;
    let allRulesMet = true;
    for (const rule of passwordRules) { // Loop through defined rules
        if (!rule.validate(newPassword)) { // Use the validation function
            const ruleElement = document.getElementById(rule.id);
            validationError = ruleElement ? ruleElement.textContent : "Password does not meet all requirements.";
            allRulesMet = false;
            break; // Stop on first failure
        }
    }

    if (!allRulesMet) {
        toastr.warning(validationError || "Password does not meet all requirements.", 'Password Rule Violation');
        return; // Stop form submission if rules fail
    }
    // --- End Final Password Rules Validation ---

    // ... (Fetch call) ...
}
````

**Explanation:**

*   **`updatePasswordRulesDisplay` Function:** This function is the core of the dynamic display logic.
    *   It gets the current value from the password input field.
    *   It iterates through the `passwordRules` array.
    *   A flag `allPreviousMet` tracks whether all rules *before* the current one in the loop have been satisfied.
    *   For each rule, it checks `allPreviousMet && rule.validate(newPassword)`.
    *   If true, the rule's `<li>` is shown in green.
    *   If false, it means either this rule failed or a previous one did. It hides the current rule and all subsequent ones. Crucially, if `allPreviousMet` was still true *before* this rule failed, it means this is the *first* failure point, so it displays this specific rule's `<li>` in red. The `allPreviousMet` flag is then set to `false`.
*   **Event Listener:** An `input` event listener is attached to the "New Password" field (`#password`). This listener calls `updatePasswordRulesDisplay` every time the user types, providing immediate feedback.
*   **Initial Call:** `updatePasswordRulesDisplay` is called once when the form is created to set the initial state (showing the first rule in red).
*   **Final Check:** Before submitting the form (`onPasswordChange`), the code loops through `passwordRules` again, using the `validate` functions to ensure all rules are met. If any fail, it shows a warning and prevents the API call.

#### Backend – Rule Enforcement (`UserController.cs`)

````csharp
using System.Text.RegularExpressions; // For Regex
using System.Collections.Generic; // For HashSet
using System.Linq; // For Linq methods like Any

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly NewsAppContext _context;
        // --- Define rules constants/readonly fields ---
        private const int MinPasswordLength = 8;
        private static readonly Regex UpperCaseRegex = new Regex(@"[A-Z]");
        // private static readonly Regex LowerCaseRegex = new Regex(@"[a-z]"); // Available if needed
        private static readonly Regex DigitRegex = new Regex(@"[0-9]");
        private static readonly Regex SpecialCharRegex = new Regex(@"[!@#$%^&*()\-_=+[\]{}|;:'"",.<>/?~]");
        private static readonly Regex RomanSequenceRegex = new Regex(@"[IVXLCDM]+"); // Uppercase only
        private static readonly HashSet<string> RequiredFruits = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "apple", "banana", "orange", "grape", "pear" };
        private const int RequiredRomanSum = 69;
        private static readonly Dictionary<char, int> RomanMap = new Dictionary<char, int> { /* ... values ... */ };
        // --- End Rules Definitions ---

        public UserController(NewsAppContext context) { _context = context; }

        // Helper function to calculate value of a single Roman numeral sequence
        private int CalculateRomanValue(string romanSequence) { /* ... implementation ... */ }

        [HttpPatch("password-update")]
        [Authorize]
        // ... (ProducesResponseType attributes) ...
        public ActionResult PasswordUpdate(PasswordUpdateDto request)
        {
            // ... (Basic request validation, user retrieval, current password check) ...

            // --- New Password Rules Validation ---
            string newPassword = request.NewPassword;
            string? validationError = null;

            // 1. Length Check
            if (newPassword.Length < MinPasswordLength)
            {
                validationError = $"Password must be at least {MinPasswordLength} characters long.";
            }
            // 2. Uppercase Check
            else if (!UpperCaseRegex.IsMatch(newPassword))
            {
                validationError = "Password needs at least one uppercase letter.";
            }
            // 3. Number Check
            else if (!DigitRegex.IsMatch(newPassword))
            {
                validationError = "Password requires at least one number.";
            }
            // 4. Special Character Check
            else if (!SpecialCharRegex.IsMatch(newPassword))
            {
                validationError = "Password lacks a required special character (!@#$ etc.).";
            }
            // 5. Fruit Check
            else if (!RequiredFruits.Any(fruit => newPassword.Contains(fruit, StringComparison.OrdinalIgnoreCase)))
            {
                validationError = "Password must contain a fruit name (apple, banana, orange, grape, pear).";
            }
            else
            {
                // 6. & 7. Roman Numeral Checks (Count and Sum)
                int totalRomanValue = 0;
                MatchCollection romanMatches = RomanSequenceRegex.Matches(newPassword);
                int romanSequenceCount = romanMatches.Count;

                if (romanSequenceCount < 2) // Check for at least two sequences
                {
                    validationError = "Password must contain at least two separate sequences of uppercase Roman numerals (e.g., 'LX' and 'IX').";
                }
                else
                {
                    foreach (Match match in romanMatches)
                    {
                        totalRomanValue += CalculateRomanValue(match.Value); // Use helper
                    }
                    // Check if the total value is exactly the required sum
                    if (totalRomanValue != RequiredRomanSum)
                    {
                        validationError = $"The total value of all Roman numeral sequences must sum up to exactly {RequiredRomanSum}. Yours sums to {totalRomanValue}. Nice try!";
                    }
                }
            }

            // Return if any validation error occurred
            if (validationError != null)
            {
                return BadRequest(validationError); // Return specific rule violation
            }
            // --- End New Password Rules Validation ---

            // ... (Final check: New vs Current, Update Password logic) ...

            return Ok("Password updated successfully.");
        }
    }
}
````

**Explanation:**

*   **Constants and Regex:** Class-level constants (`MinPasswordLength`, `RequiredRomanSum`) and pre-compiled `Regex` objects (`UpperCaseRegex`, `DigitRegex`, `SpecialCharRegex`, `RomanSequenceRegex`) are defined for efficient and consistent rule checking. A `HashSet<string>` (`RequiredFruits`) is used for case-insensitive fruit checking.
*   **Validation Sequence:** Inside the `PasswordUpdate` action, after verifying the current password, a series of `if/else if` statements checks the `newPassword` against each rule in order:
    *   Length
    *   Uppercase character
    *   Digit
    *   Special character
    *   Fruit name containment
    *   Roman numeral sequence count (at least 2)
    *   Roman numeral sequence sum (exactly 69)
*   **Roman Numeral Logic:** It uses `RomanSequenceRegex` to find all uppercase Roman numeral sequences. It checks if at least two matches are found. If so, it iterates through the matches, calculates the value of each using the `CalculateRomanValue` helper function, sums them up, and compares the total to `RequiredRomanSum`.
*   **Error Handling:** If any rule check fails, a specific error message is assigned to the `validationError` variable. The code then immediately checks if `validationError` is not null. If it has a value (meaning a rule failed), a `BadRequest` (HTTP 400) response is returned containing the specific error message, preventing the password update. The password is only updated if all checks pass (`validationError` remains null).

### [Demo Video](https://cloud.sprudello.ch/index.php/s/bQ6XZ7tmJ8kSHg8) (Click on the text if it doesn't work)
![[convertedPassword.mp4]]


# HZ4

### Logging concept

| Event                                   | Level       |
| --------------------------------------- | ----------- |
| **Authentication & Session**            |             |
| User Login Success                      | Information |
| User Login Failure (Credentials)        | Warning     |
| User Login Failure (User Not Found)     | Warning     |
| User Login Requires 2FA                 | Information |
| 2FA Verification Success                | Information |
| 2FA Verification Failure (Invalid Code) | Warning     |
| 2FA Setup Initiated                     | Information |
| 2FA Setup Completed (Enabled)           | Information |
| 2FA Setup Failed (Verification)         | Warning     |
| **Authorization**                       | dock        |
| Unauthorized Access Attempt             | Warning     |
| **Password Management**                 |             |
| Password Change Success                 | Information |
| Password Change Failure (Current Pwd)   | Warning     |
| Password Change Failure (Rule)          | Warning     |
| Password Change Failure (Same Pwd)      | Warning     |
| **Resource Management (e.g., News)**    |             |
| News Item Created                       | Information |
| News Item Updated                       | Information |
| News Item Deleted                       | Information |
| News Item Not Found                     | Warning     |
| **Errors & System Health**              |             |
| Database Operation Error                | Error       |
| Configuration Error                     | Critical    |
| Unhandled Exception                     | Error       |

---
### Logging implementation with ILogger

#### LoginController.cs

*   **Warning:** Login Attempt: Bad request
    ````csharp
    _logger.LogWarning("Login Attempt: Bad request - missing username or password.");
    ````
*   **Warning:** Login Failure: User not found
    ````csharp
    _logger.LogWarning("Login Failure: User not found for username {Username}", request.Username);
    ````
*   **Information:** Login Step: 2FA required
    ````csharp
    _logger.LogInformation("Login Step: 2FA required for User ID {UserId}", user.Id);
    ````
*   **Information:** Login Success (no 2FA required)
    ````csharp
    _logger.LogInformation("Login Success: User ID {UserId} logged in successfully (no 2FA required)", user.Id);
    ````
*   **Warning:** 2FA Verify Failure: Bad request
    ````csharp
    _logger.LogWarning("2FA Verify Failure: Bad request - missing User ID or Code. UserID Attempted: {UserId}", request?.UserId);
    ````
*   **Warning:** 2FA Verify Failure: User not found
    ````csharp
    _logger.LogWarning("2FA Verify Failure: User not found for ID {UserId}", request.UserId);
    ````
*   **Warning:** 2FA Verify Failure: 2FA not enabled/Setup Incomplete
    ````csharp
    _logger.LogWarning("2FA Verify Failure: 2FA not enabled or secret missing for User ID {UserId}", request.UserId);
    ````
*   **Information:** 2FA Verify Success
    ````csharp
    _logger.LogInformation("2FA Verify Success: User ID {UserId} completed login", user.Id);
    ````
*   **Warning:** 2FA Verify Failure: Invalid code
    ````csharp
    _logger.LogWarning("2FA Verify Failure: Invalid code provided for User ID {UserId}", request.UserId);
    ````
*   **Critical:** JWT Key is missing (in GenerateJwtToken)
    ````csharp
    _logger.LogCritical("JWT Key is missing or empty in configuration. Cannot generate token.");
    ````
#### NewsController.cs

*   **Error:** Error retrieving news
    ````csharp
    _logger.LogError(ex, "Error retrieving news");
    ````
*   **Warning:** Get News Failure: Not Found
    ````csharp
    _logger.LogWarning("Get News Failure: News item not found for ID {NewsId}", id);
    ````
*   **Error:** Error retrieving news with ID
    ````csharp
    _logger.LogError(ex, "Error retrieving news with ID {NewsId}", id);
    ````
*   **Warning:** News Create Attempt: Bad Request
    ````csharp
    _logger.LogWarning("News Create Attempt: Bad request - request body was null.");
    ````
*   **Information:** News Created
    ````csharp
     _logger.LogInformation("News Created: News item {NewsId} created by User ID {UserId}", newNews.Id, request.AuthorId);
    ````
*   **Error:** News Create Failure: DB Error
    ````csharp
     _logger.LogError(ex, "News Create Failure: Database error occurred for User ID {UserId}", request.AuthorId);
    ````
*   **Error:** News Create Failure: Unexpected Error
    ````csharp
     _logger.LogError(ex, "News Create Failure: Unexpected error occurred for User ID {UserId}", request.AuthorId);
    ````
*   **Warning:** News Update Attempt: Bad Request (Note: Log message says "Create")
    ````csharp
    _logger.LogWarning("News Create Attempt: Bad request - request body was null.");
    ````
*   **Warning:** News Update Failure: Not Found
    ````csharp
    _logger.LogWarning("News Update Failure: News item not found for ID {NewsId}, attempted by User ID {UserId}", id, request.AuthorId);
    ````
*   **Information:** News Updated
    ````csharp
    _logger.LogInformation("News Updated: News item {NewsId} updated by User ID {UserId}", id, request.AuthorId);
    ````
*   **Error:** News Update Failure: DB Error
    ````csharp
    _logger.LogError(ex, "News Update Failure: Database error occurred for User ID {UserId}", request.AuthorId);
    ````
*   **Error:** News Update Failure: Unexpected Error
    ````csharp
    _logger.LogError(ex, "News Update Failure: Unexpected error occurred for User ID {UserId}", request.AuthorId);
    ````
*   **Warning:** News Delete Failure: Not Found
    ````csharp
    _logger.LogWarning("News Delete Failure: News item not found for ID {NewsId}", id);
    ````
*   **Information:** News Deleted
    ````csharp
    _logger.LogInformation("News Deleted: News item {NewsId} deleted", id);
    ````
*   **Error:** News Delete Failure: DB Error
    ````csharp
    _logger.LogError(ex, "News Delete Failure: Database error occurred for News ID {NewsId}", id);
    ````
*   **Error:** News Delete Failure: Unexpected Error
    ````csharp
    _logger.LogError(ex, "News Delete Failure: Unexpected error occurred for News ID {NewsId}", id);
    ````

#### TwoFactorAuthController.cs

*   **Warning:** 2FA Setup: Unauthorized
    ````csharp
    _logger.LogWarning("2FA Setup: Unauthorized access attempt (GetCurrentUserId returned null).");
    ````
*   **Error:** 2FA Setup: DB Find Error
    ````csharp
    _logger.LogError(ex, "2FA Setup: Database error finding User ID {UserId}", userId.Value);
    ````
*   **Information:** 2FA Setup: Info Provided
    ````csharp
    _logger.LogInformation("2FA Setup: Provided setup info for User ID {UserId}", userId.Value);
    ````
*   **Warning:** 2FA Enable Verify: Bad Request
    ````csharp
     _logger.LogWarning("2FA Enable Verify: Bad request - Code missing in request body.");
    ````
*   **Warning:** 2FA Enable Verify: Unauthorized
    ````csharp
    _logger.LogWarning("2FA Enable Verify: Unauthorized access attempt (GetCurrentUserId returned null).");
    ````
*   **Warning:** 2FA Enable Verify: User Not Found
    ````csharp
     _logger.LogWarning("2FA Enable Verify: User not found for ID {UserId}", userId.Value);
    ````
*   **Warning:** 2FA Enable Verify: Setup Incomplete
    ````csharp
     _logger.LogWarning("2FA Enable Verify: 2FA setup not initiated (secret missing) for User ID {UserId}", userId.Value);
    ````
*   **Information:** 2FA Enable Verify: Success
    ````csharp
    _logger.LogInformation("2FA Enable Verify: Successfully verified and enabled for User ID {UserId}", userId.Value);
    ````
*   **Error:** 2FA Enable Verify: DB Enable Error
    ````csharp
    _logger.LogError(ex, "2FA Enable Verify: Database error enabling 2FA for User ID {UserId}", userId.Value);
    ````
*   **Error:** 2FA Enable Verify: Unexpected Error
    ````csharp
    _logger.LogError(ex, "2FA Enable Verify: Unexpected error enabling 2FA for User ID {UserId}", userId.Value);
    ````
*   **Warning:** 2FA Enable Verify: Invalid Code
    ````csharp
    _logger.LogWarning("2FA Enable Verify: Verification failed (Invalid Code) for User ID {UserId}", userId.Value);
    ````
*   **Warning:** GetCurrentUserId: Could not parse User ID
    ````csharp
    _logger.LogWarning("GetCurrentUserId: Could not parse User ID from claims. Claim value: {ClaimValue}", userIdClaim);
    ````

#### UserController.cs

*   **Warning:** Password Update Attempt: Bad Request
    ````csharp
    _logger.LogWarning("Password Update Attempt: Bad request - missing current or new password.");
    ````
*   **Warning:** Password Update Failure: Unauthorized
    ````csharp
    _logger.LogWarning("Password Update Failure: Unauthorized attempt for User ID {TargetUserId} by User ID {ClaimedUserId}", request.UserId, currentUserIdClaim ?? "null");
    ````
*   **Warning:** Password Update Failure: User Not Found
    ````csharp
    _logger.LogWarning("Password Update Failure: User not found for ID {UserId}", request.UserId);
    ````
*   **Warning:** Password Update Failure: Incorrect Current Pwd
    ````csharp
    _logger.LogWarning("Password Update Failure: Incorrect current password for User ID {UserId}", request.UserId);
    ````
*   **Warning:** Password Update Failure: Rule Violation
    ````csharp
    _logger.LogWarning("Password Update Failure: Rule violation for User ID {UserId}", request.UserId);
    ````
*   **Warning:** Password Update Failure: Same Password
    ````csharp
    _logger.LogWarning("Password Update Failure: New password same as current for User ID {UserId}", request.UserId);
    ````
*   **Information:** Password Update Success
    ````csharp
    _logger.LogInformation("Password Update Success: Password changed for User ID {UserId}", request.UserId);
    ````
*   **Error:** Password Update Failure: DB Save Error
    ````csharp
    _logger.LogError(ex, "Password Update Failure: Database error occurred while saving password for User ID {UserId}", request.UserId);
    ````
*   **Error:** Password Update Failure: Unexpected Error
    ````csharp
     _logger.LogError(ex, "Password Update Failure: Unexpected error occurred while saving password for User ID {UserId}", request.UserId);
    ````

# Critical Reflection from HZ1 to HZ4

### HZ1

In HZ1 I have learned about SQL injections, ransomware, and XSS attacks. 
