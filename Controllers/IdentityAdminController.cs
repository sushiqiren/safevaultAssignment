using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controllers
{
    /// <summary>
    /// Admin-only controller for managing users and system configuration with ASP.NET Identity.
    /// All endpoints require Admin role via JWT authorization.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Policy = "AdminPolicy")]
    public class IdentityAdminController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<IdentityAdminController> _logger;

        public IdentityAdminController(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<IdentityAdminController> logger)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
        }

        /// <summary>
        /// Gets all users in the system. Admin only.
        /// </summary>
        [HttpGet("users")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> GetAllUsers()
        {
            try
            {
                var users = await _userManager.Users
                    .OrderByDescending(u => u.CreatedAt)
                    .ToListAsync();

                var userList = new List<object>();
                foreach (var user in users)
                {
                    var roles = await _userManager.GetRolesAsync(user);
                    var isLockedOut = await _userManager.IsLockedOutAsync(user);

                    userList.Add(new
                    {
                        user.Id,
                        user.UserName,
                        user.Email,
                        user.FullName,
                        Roles = roles,
                        user.CreatedAt,
                        user.UpdatedAt,
                        user.LastLoginAt,
                        user.IsActive,
                        IsLockedOut = isLockedOut,
                        LockoutEnd = user.LockoutEnd
                    });
                }

                return Ok(new
                {
                    totalUsers = userList.Count,
                    users = userList
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving all users");
                return StatusCode(500, new { message = "Error retrieving users" });
            }
        }

        /// <summary>
        /// Gets a specific user by ID. Admin only.
        /// </summary>
        [HttpGet("users/{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            var roles = await _userManager.GetRolesAsync(user);
            var isLockedOut = await _userManager.IsLockedOutAsync(user);

            return Ok(new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.FullName,
                Roles = roles,
                user.CreatedAt,
                user.UpdatedAt,
                user.LastLoginAt,
                user.IsActive,
                IsLockedOut = isLockedOut,
                LockoutEnd = user.LockoutEnd
            });
        }

        /// <summary>
        /// Gets user statistics. Admin only.
        /// </summary>
        [HttpGet("statistics")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> GetStatistics()
        {
            try
            {
                var totalUsers = await _userManager.Users.CountAsync();
                var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
                var moderatorUsers = await _userManager.GetUsersInRoleAsync("Moderator");
                var regularUsers = await _userManager.GetUsersInRoleAsync("User");
                
                var lockedAccounts = await _userManager.Users
                    .CountAsync(u => u.LockoutEnd.HasValue && u.LockoutEnd.Value > DateTimeOffset.UtcNow);
                
                var recentLogins = await _userManager.Users
                    .CountAsync(u => u.LastLoginAt.HasValue && u.LastLoginAt.Value > DateTime.UtcNow.AddDays(-7));

                return Ok(new
                {
                    totalUsers,
                    usersByRole = new
                    {
                        admins = adminUsers.Count,
                        moderators = moderatorUsers.Count,
                        users = regularUsers.Count
                    },
                    lockedAccounts,
                    recentLogins
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving statistics");
                return StatusCode(500, new { message = "Error retrieving statistics" });
            }
        }

        /// <summary>
        /// Changes a user's role. Admin only.
        /// </summary>
        [HttpPut("users/{id}/role")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> ChangeUserRole(string id, [FromBody] ChangeRoleRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            // Verify role exists
            if (!await _roleManager.RoleExistsAsync(request.Role))
                return BadRequest(new { message = "Invalid role specified" });

            // Remove from all current roles
            var currentRoles = await _userManager.GetRolesAsync(user);
            await _userManager.RemoveFromRolesAsync(user, currentRoles);

            // Add to new role
            var result = await _userManager.AddToRoleAsync(user, request.Role);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to change role for user {UserId}: {Errors}", 
                    id, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
            }

            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Admin changed user {UserId} role to {Role}", id, request.Role);

            return Ok(new { message = "User role updated successfully", newRole = request.Role });
        }

        /// <summary>
        /// Locks a user account. Admin only.
        /// </summary>
        [HttpPost("users/{id}/lock")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> LockUser(string id, [FromBody] LockUserRequest? request = null)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            var lockoutEnd = request?.LockoutEnd ?? DateTimeOffset.UtcNow.AddYears(100); // Permanent if not specified
            var result = await _userManager.SetLockoutEndDateAsync(user, lockoutEnd);
            
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to lock user {UserId}", id);
                return BadRequest(new { message = "Failed to lock user" });
            }

            _logger.LogInformation("Admin locked user {UserId} until {LockoutEnd}", id, lockoutEnd);

            return Ok(new { message = "User locked successfully", lockoutEnd });
        }

        /// <summary>
        /// Unlocks a user account. Admin only.
        /// </summary>
        [HttpPost("users/{id}/unlock")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> UnlockUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            var result = await _userManager.SetLockoutEndDateAsync(user, null);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to unlock user {UserId}", id);
                return BadRequest(new { message = "Failed to unlock user" });
            }

            // Reset failed login attempts
            await _userManager.ResetAccessFailedCountAsync(user);

            _logger.LogInformation("Admin unlocked user {UserId}", id);

            return Ok(new { message = "User unlocked successfully" });
        }

        /// <summary>
        /// Deactivates a user account (soft delete). Admin only.
        /// </summary>
        [HttpPost("users/{id}/deactivate")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> DeactivateUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            user.IsActive = false;
            user.UpdatedAt = DateTime.UtcNow;
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to deactivate user {UserId}", id);
                return BadRequest(new { message = "Failed to deactivate user" });
            }

            _logger.LogInformation("Admin deactivated user {UserId}", id);

            return Ok(new { message = "User deactivated successfully" });
        }

        /// <summary>
        /// Reactivates a user account. Admin only.
        /// </summary>
        [HttpPost("users/{id}/activate")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> ActivateUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            user.IsActive = true;
            user.UpdatedAt = DateTime.UtcNow;
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to activate user {UserId}", id);
                return BadRequest(new { message = "Failed to activate user" });
            }

            _logger.LogInformation("Admin activated user {UserId}", id);

            return Ok(new { message = "User activated successfully" });
        }

        /// <summary>
        /// Deletes a user account permanently. Admin only.
        /// </summary>
        [HttpDelete("users/{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            // Prevent deleting the last admin
            if (await _userManager.IsInRoleAsync(user, "Admin"))
            {
                var adminCount = (await _userManager.GetUsersInRoleAsync("Admin")).Count;
                if (adminCount <= 1)
                    return BadRequest(new { message = "Cannot delete the last admin user" });
            }

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to delete user {UserId}: {Errors}", 
                    id, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
            }

            _logger.LogInformation("Admin deleted user {UserId}", id);

            return Ok(new { message = "User deleted successfully" });
        }

        /// <summary>
        /// Resets a user's password. Admin only.
        /// </summary>
        [HttpPost("users/{id}/reset-password")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> ResetUserPassword(string id, [FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            // Remove current password
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);

            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to reset password for user {UserId}: {Errors}", 
                    id, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
            }

            _logger.LogInformation("Admin reset password for user {UserId}", id);

            return Ok(new { message = "Password reset successfully" });
        }
    }

    // DTOs for admin operations
    public class ChangeRoleRequest
    {
        public string Role { get; set; } = string.Empty;
    }

    public class LockUserRequest
    {
        public DateTimeOffset LockoutEnd { get; set; }
    }

    public class ResetPasswordRequest
    {
        public string NewPassword { get; set; } = string.Empty;
    }
}
