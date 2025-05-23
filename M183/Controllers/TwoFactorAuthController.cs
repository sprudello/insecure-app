using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using M183.Data;
using M183.Models;
using M183.Controllers.Dto;
using Google.Authenticator;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Google.Authenticator;
using Microsoft.Extensions.Logging;

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // Require user to be logged in for all actions here
    public class TwoFactorAuthController : ControllerBase
    {
        private readonly NewsAppContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<TwoFactorAuthController> _logger;

        // Use a fixed issuer name, potentially from configuration
        private const string Issuer = "InsecureApp";

        public TwoFactorAuthController(NewsAppContext context, IConfiguration configuration, ILogger<TwoFactorAuthController> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
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
            if (userId == null) 
            {
                _logger.LogWarning("2FA Setup: Unauthorized access attempt (GetCurrentUserId returned null).");
                return Unauthorized();
            }

            User? user;
            try
            {
                user = await _context.Users.FindAsync(userId.Value);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "2FA Setup: Database error finding User ID {UserId}", userId.Value);
                return StatusCode(500, "Database error occurred.");
            }

            // Generate a new secret if one doesn't exist or if 2FA is not yet enabled
            if (string.IsNullOrEmpty(user.TwoFactorSecret) || !user.IsTwoFactorEnabled)
            {
                user.TwoFactorSecret = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10); // Generate a simple secret
                await _context.SaveChangesAsync();
            }

            var tfa = new TwoFactorAuthenticator();
            // Use username in the QR code label for clarity in authenticator apps
            var setupInfo = tfa.GenerateSetupCode(Issuer, user.Username, user.TwoFactorSecret, false);
            
            _logger.LogInformation("2FA Setup: Provided setup info for User ID {UserId}", userId.Value);
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
            if (request == null || string.IsNullOrEmpty(request.Code))
            {
                 _logger.LogWarning("2FA Enable Verify: Bad request - Code missing in request body.");
                return BadRequest("Code is required.");
            }

            var userId = GetCurrentUserId();
            if (userId == null)
            {
                
                _logger.LogWarning("2FA Enable Verify: Unauthorized access attempt (GetCurrentUserId returned null).");
                return Unauthorized();
            }
            var user = await _context.Users.FindAsync(userId.Value);
            if (user == null)
            {
                 _logger.LogWarning("2FA Enable Verify: User not found for ID {UserId}", userId.Value);
                return NotFound("User not found.");
            }
            if (string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                 _logger.LogWarning("2FA Enable Verify: 2FA setup not initiated (secret missing) for User ID {UserId}", userId.Value);
                return BadRequest("2FA setup not initiated or secret missing.");
            }

            var tfa = new TwoFactorAuthenticator();
            bool isValid = tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, request.Code);

            if (isValid)
            {
                user.IsTwoFactorEnabled = true;
                try
                {
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("2FA Enable Verify: Successfully verified and enabled for User ID {UserId}", userId.Value);
                    return Ok("Two-Factor Authentication enabled successfully.");
                }
                catch (DbUpdateException ex)
                {
                    _logger.LogError(ex, "2FA Enable Verify: Database error enabling 2FA for User ID {UserId}", userId.Value);
                    return StatusCode(500, "An error occurred while enabling 2FA.");
                }
                 catch (Exception ex)
                {
                    _logger.LogError(ex, "2FA Enable Verify: Unexpected error enabling 2FA for User ID {UserId}", userId.Value);
                    return StatusCode(500, "An unexpected error occurred while enabling 2FA.");
                }
            }
            else
            {
                _logger.LogWarning("2FA Enable Verify: Verification failed (Invalid Code) for User ID {UserId}", userId.Value);
                return BadRequest("Invalid code.");
            }
        }

        private int? GetCurrentUserId()
        {
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (int.TryParse(userIdClaim, out int userId))
            {
                return userId;
            }
            _logger.LogWarning("GetCurrentUserId: Could not parse User ID from claims. Claim value: {ClaimValue}", userIdClaim);
            return null;
        }
    }
}