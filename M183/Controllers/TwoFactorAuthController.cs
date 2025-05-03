using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using M183.Data;
using M183.Models;
using M183.Controllers.Dto;
using Google.Authenticator;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Google.Authenticator;

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // Require user to be logged in for all actions here
    public class TwoFactorAuthController : ControllerBase
    {
        private readonly NewsAppContext _context;
        private readonly IConfiguration _configuration;

        // Use a fixed issuer name, potentially from configuration
        private const string Issuer = "InsecureApp";

        public TwoFactorAuthController(NewsAppContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        /// <summary>
        /// Generates setup information for 2FA (secret and QR code URL).
        /// </summary>
        [HttpGet("setup")]
        [ProducesResponseType(typeof(TwoFactorSetupDto), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<TwoFactorSetupDto>> GetSetupInfo()
        {
            var userId = GetCurrentUserId();
            if (userId == null) return Unauthorized();

            var user = await _context.Users.FindAsync(userId.Value);
            if (user == null) return NotFound("User not found.");

            // Generate a new secret if one doesn't exist or if 2FA is not yet enabled
            if (string.IsNullOrEmpty(user.TwoFactorSecret) || !user.IsTwoFactorEnabled)
            {
                user.TwoFactorSecret = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10); // Generate a simple secret
                await _context.SaveChangesAsync();
            }

            var tfa = new TwoFactorAuthenticator();
            // Use username in the QR code label for clarity in authenticator apps
            var setupInfo = tfa.GenerateSetupCode(Issuer, user.Username, user.TwoFactorSecret, false);

            return Ok(new TwoFactorSetupDto
            {
                ManualEntryKey = setupInfo.ManualEntryKey,
                QrCodeImageUrl = setupInfo.QrCodeSetupImageUrl
            });
        }

        /// <summary>
        /// Verifies the TOTP code and enables 2FA for the user.
        /// </summary>
        [HttpPost("verify")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> VerifyAndEnable([FromBody] TwoFactorVerifyDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.Code)) return BadRequest("Code is required.");

            var userId = GetCurrentUserId();
            if (userId == null) return Unauthorized();

            var user = await _context.Users.FindAsync(userId.Value);
            if (user == null) return NotFound("User not found.");
            if (string.IsNullOrEmpty(user.TwoFactorSecret)) return BadRequest("2FA setup not initiated.");

            var tfa = new TwoFactorAuthenticator();
            bool isValid = tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, request.Code);

            if (isValid)
            {
                user.IsTwoFactorEnabled = true;
                await _context.SaveChangesAsync();
                return Ok("Two-Factor Authentication enabled successfully.");
            }

            return BadRequest("Invalid code.");
        }

        private int? GetCurrentUserId()
        {
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (int.TryParse(userIdClaim, out int userId))
            {
                return userId;
            }
            return null;
        }
    }
}