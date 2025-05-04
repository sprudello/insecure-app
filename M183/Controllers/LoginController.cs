using M183.Controllers.Dto;
using M183.Controllers.Helper;
using M183.Data;
using M183.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Google.Authenticator;
using Microsoft.Extensions.Logging;

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly NewsAppContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<LoginController> _logger;

        public LoginController(NewsAppContext context, IConfiguration configuration, ILogger<LoginController> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
        }

        /// <summary>
        /// Login a user using password and username. May require 2FA step.
        /// </summary>
        /// <response code="200">Login successful OR 2FA required</response>
        /// <response code="400">Bad request</response>
        /// <response code="401">Login failed (bad credentials)</response>
        [HttpPost]
        [ProducesResponseType(typeof(LoginResponseDto), 200)] // Updated response type
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<ActionResult<LoginResponseDto>> Login(LoginDto request) // Changed return type
        {
            if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                _logger.LogWarning("Login Attempt: Bad request - missing username or password.");
                return BadRequest("Username and password are required.");
            }

            string hashedPassword = MD5Helper.ComputeMD5Hash(request.Password);

            User? user = await _context.Users
                .Where(u => u.Username == request.Username && u.Password == hashedPassword)
                .FirstOrDefaultAsync();

            if (user == null)
            {
                _logger.LogWarning("Login Failure: User not found for username {Username}", request.Username);
                return Unauthorized("Invalid credentials.");
            }

            // Check if 2FA is enabled
            if (user.IsTwoFactorEnabled)
            {
                _logger.LogInformation("Login Step: 2FA required for User ID {UserId}", user.Id);
                return Ok(new LoginResponseDto { RequiresTwoFactor = true, UserId = user.Id });
            }

            // 2FA not enabled, generate JWT token immediately
            var token = GenerateJwtToken(user);
            _logger.LogInformation("Login Success: User ID {UserId} logged in successfully (no 2FA required)", user.Id);

            return Ok(new LoginResponseDto
            {
                RequiresTwoFactor = false,
                Id = user.Id,
                Username = user.Username,
                IsAdmin = user.IsAdmin,
                Token = token
            });
        }

        /// <summary>
        /// Verifies the 2FA code provided after initial login.
        /// </summary>
        /// <response code="200">2FA successful, returns user info and JWT</response>
        /// <response code="400">Bad request or invalid code</response>
        /// <response code="404">User not found</response>
        [HttpPost("verify-2fa")]
        [ProducesResponseType(typeof(LoginResponseDto), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<LoginResponseDto>> VerifyTwoFactor(TwoFactorLoginDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.Code) || request.UserId <= 0)
            {
                _logger.LogWarning("2FA Verify Failure: Bad request - missing User ID or Code. UserID Attempted: {UserId}", request?.UserId);
                return BadRequest("User ID and code are required.");
            }

            var user = await _context.Users.FindAsync(request.UserId);
            if (user == null)
            {
                _logger.LogWarning("2FA Verify Failure: User not found for ID {UserId}", request.UserId);
                return NotFound("User not found.");
            }

            if (!user.IsTwoFactorEnabled || string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                _logger.LogWarning("2FA Verify Failure: 2FA not enabled or secret missing for User ID {UserId}", request.UserId);
                return BadRequest("2FA is not enabled for this user.");
            }

            var tfa = new TwoFactorAuthenticator();
            bool isValid = tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, request.Code);

            if (isValid)
            {
                // Code is valid, generate JWT token
                var token = GenerateJwtToken(user);
                _logger.LogInformation("2FA Verify Success: User ID {UserId} completed login", user.Id);
                return Ok(new LoginResponseDto
                {
                    RequiresTwoFactor = false, // Final step, so false
                    Id = user.Id,
                    Username = user.Username,
                    IsAdmin = user.IsAdmin,
                    Token = token
                });
            }
            else
            {
                _logger.LogWarning("2FA Verify Failure: Invalid code provided for User ID {UserId}", request.UserId);
                return BadRequest("Invalid 2FA code.");
            }
        }

        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtKey = _configuration["Jwt:Key"];
            if (string.IsNullOrEmpty(jwtKey))
            {
                _logger.LogCritical("JWT Key is missing or empty in configuration. Cannot generate token.");
                throw new InvalidOperationException("JWT Key is not configured properly.");
            }
            var key = Encoding.ASCII.GetBytes(jwtKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Role, user.IsAdmin ? "Admin" : "User")
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
