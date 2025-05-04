using M183.Controllers.Dto;
using M183.Controllers.Helper;
using M183.Data;
using M183.Models; // Added for User model reference
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly NewsAppContext _context;
        // Define rules constants/readonly fields
        private const int MinPasswordLength = 8; // Updated length
        private static readonly Regex UpperCaseRegex = new Regex(@"[A-Z]");
        private static readonly Regex LowerCaseRegex = new Regex(@"[a-z]"); 
        private static readonly Regex DigitRegex = new Regex(@"[0-9]");
        private static readonly Regex SpecialCharRegex = new Regex(@"[!@#$%^&*()\-_=+[\]{}|;:'"",.<>/?~]");
        // Find sequences of ONLY uppercase Roman numerals
        private static readonly Regex RomanSequenceRegex = new Regex(@"[IVXLCDM]+");
        private static readonly HashSet<string> RequiredFruits = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "apple", "banana", "orange", "grape", "pear" };
        private const int RequiredRomanSum = 69; // Required sum

        // Dictionary for Roman numeral values
        private static readonly Dictionary<char, int> RomanMap = new Dictionary<char, int>
        {
            { 'I', 1 }, { 'V', 5 }, { 'X', 10 }, { 'L', 50 }, { 'C', 100 }, { 'D', 500 }, { 'M', 1000 }
        };

        public UserController(NewsAppContext context)
        {
            _context = context;
        }

        
        private int CalculateRomanValue(string romanSequence)
        {
            int totalValue = 0;
            int length = romanSequence.Length;
            for (int i = 0; i < length; i++)
            {
                // Ensure the character is a valid Roman numeral (should be guaranteed by regex, but good practice)
                if (!RomanMap.TryGetValue(romanSequence[i], out int currentVal))
                {
                     // Handle unexpected character if necessary, though regex should prevent this
                     return 0; // Or throw an exception
                }

                // Check next character for subtractive notation
                if (i + 1 < length && RomanMap.TryGetValue(romanSequence[i + 1], out int nextVal) && nextVal > currentVal)
                {
                    totalValue -= currentVal; // Subtract current value (like IV, IX)
                }
                else
                {
                    totalValue += currentVal; // Add current value
                }
            }
            return totalValue;
        }


        /// <summary>
        /// update password
        /// </summary>
        /// <response code="200">Password updated successfully</response>
        /// <response code="400">Bad request (e.g., missing fields, incorrect current password, rule violation)</response>
        /// <response code="401">Unauthorized (JWT invalid or user mismatch)</response>
        /// <response code="404">User not found</response>
        [HttpPatch("password-update")]
        [Authorize]
        [ProducesResponseType(200)]
        [ProducesResponseType(typeof(string), 400)] // Specify string for error message
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        public ActionResult PasswordUpdate(PasswordUpdateDto request)
        {
            // --- Basic Request Validation ---
            if (request == null || string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrEmpty(request.NewPassword))
                return BadRequest("Current and new passwords are required.");

            // --- Authorization and User Retrieval ---
            var currentUserIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!int.TryParse(currentUserIdClaim, out int currentUserId) || currentUserId != request.UserId)
                return Unauthorized("User ID mismatch or invalid token.");

            var user = _context.Users.Find(request.UserId);
            if (user == null) return NotFound($"User {request.UserId} not found");

            // --- Current Password Verification ---
            string hashedCurrentPassword = MD5Helper.ComputeMD5Hash(request.CurrentPassword);
            if (user.Password != hashedCurrentPassword) return BadRequest("Incorrect current password.");

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
                        totalRomanValue += CalculateRomanValue(match.Value);
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
                return BadRequest(validationError);
            }
            // --- End New Password Rules Validation ---

            // --- Final Check: New vs Current Password ---
            string hashedNewPassword = MD5Helper.ComputeMD5Hash(newPassword);
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
    }
}