using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;

namespace SafeVault.Controllers
{
    /// <summary>
    /// API Controller for managing user profile operations with JWT authorization.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Policy = "UserPolicy")]
    public class IdentityUsersController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<IdentityUsersController> _logger;

        public IdentityUsersController(
            UserManager<ApplicationUser> userManager,
            ILogger<IdentityUsersController> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        /// <summary>
        /// Gets the current user's profile.
        /// </summary>
        [HttpGet("profile")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> GetProfile()
        {
            var userId = User.FindFirst("userId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { message = "User not found" });

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                user.Id,
                user.Email,
                user.UserName,
                user.FullName,
                Roles = roles,
                user.CreatedAt,
                user.LastLoginAt
            });
        }

        /// <summary>
        /// Updates the current user's profile.
        /// </summary>
        [HttpPut("profile")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userId = User.FindFirst("userId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { message = "User not found" });

            // Update full name if provided
            if (!string.IsNullOrWhiteSpace(request.FullName))
            {
                // Sanitize to prevent stored XSS
                user.FullName = System.Net.WebUtility.HtmlEncode(request.FullName.Trim());
            }

            // Update email if provided and different
            if (!string.IsNullOrWhiteSpace(request.Email) && request.Email != user.Email)
            {
                // Trim and sanitize email
                var sanitizedEmail = System.Net.WebUtility.HtmlEncode(request.Email.Trim());

                // Check if email already exists
                var existingUser = await _userManager.FindByEmailAsync(sanitizedEmail);
                if (existingUser != null && existingUser.Id != userId)
                {
                    return BadRequest(new { message = "Email already in use" });
                }

                user.Email = sanitizedEmail;
                user.UserName = sanitizedEmail; // Keep username in sync with email
            }

            user.UpdatedAt = DateTime.UtcNow;
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to update profile for user {UserId}: {Errors}", 
                    userId, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
            }

            _logger.LogInformation("User {UserId} updated their profile", userId);

            return Ok(new { message = "Profile updated successfully" });
        }

        /// <summary>
        /// Deletes the current user's account.
        /// </summary>
        [HttpDelete("profile")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> DeleteAccount()
        {
            var userId = User.FindFirst("userId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { message = "User not found" });

            // Prevent deleting admin accounts
            if (await _userManager.IsInRoleAsync(user, "Admin"))
            {
                return BadRequest(new { message = "Admin accounts cannot be self-deleted" });
            }

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to delete account for user {UserId}: {Errors}", 
                    userId, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
            }

            _logger.LogInformation("User {UserId} deleted their account", userId);

            return Ok(new { message = "Account deleted successfully" });
        }
    }

    // DTO for profile updates
    public class UpdateProfileRequest
    {
        [StringLength(100, MinimumLength = 2, ErrorMessage = "Full name must be between 2 and 100 characters")]
        [RegularExpression(@"^[a-zA-Z\s\-'.]+$", ErrorMessage = "Full name can only contain letters, spaces, hyphens, apostrophes, and periods")]
        public string? FullName { get; set; }
        
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [StringLength(100, ErrorMessage = "Email cannot exceed 100 characters")]
        public string? Email { get; set; }
    }
}
