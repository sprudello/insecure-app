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
                return BadRequest();
            }

            string hashedPassword = MD5Helper.ComputeMD5Hash(request.Password);

            User? user = await _context.Users
                .Where(u => u.Username == request.Username && u.Password == hashedPassword)
                .FirstOrDefaultAsync();

            if (user == null)
            {
                return Unauthorized("Invalid credentials.");
            }

            // Check if 2FA is enabled
            if (user.IsTwoFactorEnabled)
            {
                // Return response indicating 2FA is required
                return Ok(new LoginResponseDto { RequiresTwoFactor = true, UserId = user.Id });
            }

            // 2FA not enabled, generate JWT token immediately
            var token = GenerateJwtToken(user);

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
                return BadRequest("User ID and code are required.");
            }

            var user = await _context.Users.FindAsync(request.UserId);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            if (!user.IsTwoFactorEnabled || string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                return BadRequest("2FA is not enabled for this user.");
            }

            var tfa = new TwoFactorAuthenticator();
            bool isValid = tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, request.Code);

            if (isValid)
            {
                // Code is valid, generate JWT token
                var token = GenerateJwtToken(user);
                return Ok(new LoginResponseDto
                {
                    RequiresTwoFactor = false, // Final step, so false
                    Id = user.Id,
                    Username = user.Username,
                    IsAdmin = user.IsAdmin,
                    Token = token
                });
            }

            return BadRequest("Invalid 2FA code.");
        }

        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"] ?? "defaultSecretKeyForJwtIfConfigurationNotProvided12345");
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
