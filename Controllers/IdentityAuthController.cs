using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Models.DTOs;
using SafeVault.Services;

namespace SafeVault.Controllers
{
    /// <summary>
    /// Authentication controller using ASP.NET Identity and JWT tokens.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class IdentityAuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly ILogger<IdentityAuthController> _logger;

        public IdentityAuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IJwtTokenService jwtTokenService,
            ILogger<IdentityAuthController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtTokenService = jwtTokenService;
            _logger = logger;
        }

        /// <summary>
        /// Register a new user account.
        /// </summary>
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthenticationResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Check if email already exists
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                _logger.LogWarning("Registration attempt with existing email: {Email}", request.Email);
                return BadRequest(new { Message = "Email already registered" });
            }

            // Create new user
            var user = new ApplicationUser
            {
                Email = request.Email,
                UserName = request.Email, // Using email as username
                FullName = System.Net.WebUtility.HtmlEncode(request.FullName), // Prevent stored XSS
                EmailConfirmed = true, // Auto-confirm for now
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to create user {Email}: {Errors}", 
                    request.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
            }

            // Assign default "User" role
            await _userManager.AddToRoleAsync(user, "User");

            _logger.LogInformation("New user registered: {UserId} ({Email})", user.Id, user.Email);

            // Generate tokens
            var authResponse = await _jwtTokenService.GenerateTokenAsync(user);

            return CreatedAtAction(nameof(GetCurrentUser), new { id = user.Id }, authResponse);
        }

        /// <summary>
        /// Login with email and password.
        /// </summary>
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthenticationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                // Add delay to prevent timing attacks that could determine valid emails
                await Task.Delay(TimeSpan.FromMilliseconds(200));
                _logger.LogWarning("Login attempt with non-existent email: {Email}", request.Email);
                return Unauthorized(new { Message = "Invalid email or password" });
            }

            if (!user.IsActive)
            {
                _logger.LogWarning("Login attempt for inactive user: {UserId}", user.Id);
                return Unauthorized(new { Message = "Account is disabled" });
            }

            // Check lockout
            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Login attempt for locked out user: {UserId}", user.Id);
                return Unauthorized(new { Message = "Account is locked. Please try again later." });
            }

            // Verify password
            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (!result.Succeeded)
            {
                // Add delay to prevent timing attacks
                await Task.Delay(TimeSpan.FromMilliseconds(200));
                
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User {UserId} locked out after failed login", user.Id);
                    return Unauthorized(new { Message = "Account is locked due to multiple failed login attempts" });
                }

                _logger.LogWarning("Failed login attempt for user: {Email}", request.Email);
                return Unauthorized(new { Message = "Invalid email or password" });
            }

            // Update last login
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User logged in: {UserId} ({Email})", user.Id, user.Email);

            // Generate tokens
            var authResponse = await _jwtTokenService.GenerateTokenAsync(user);

            return Ok(authResponse);
        }

        /// <summary>
        /// Refresh access token using refresh token.
        /// </summary>
        [HttpPost("refresh-token")]
        [ProducesResponseType(typeof(AuthenticationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var response = await _jwtTokenService.RefreshTokenAsync(request);
            if (response == null)
            {
                _logger.LogWarning("Invalid refresh token attempt");
                return BadRequest(new { Message = "Invalid or expired refresh token" });
            }

            return Ok(response);
        }

        /// <summary>
        /// Revoke refresh token (logout).
        /// </summary>
        [Authorize]
        [HttpPost("logout")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Logout([FromBody] string refreshToken)
        {
            var userId = User.FindFirst("userId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return BadRequest(new { Message = "Invalid user" });

            var result = await _jwtTokenService.RevokeTokenAsync(userId, refreshToken);
            if (!result)
            {
                _logger.LogWarning("Failed to revoke token for user {UserId}", userId);
                return BadRequest(new { Message = "Invalid refresh token" });
            }

            _logger.LogInformation("User logged out: {UserId}", userId);
            return Ok(new { Message = "Logged out successfully" });
        }

        /// <summary>
        /// Revoke all refresh tokens (logout from all devices).
        /// </summary>
        [Authorize]
        [HttpPost("logout-all")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> LogoutAll()
        {
            var userId = User.FindFirst("userId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return BadRequest(new { Message = "Invalid user" });

            await _jwtTokenService.RevokeAllTokensAsync(userId);

            _logger.LogInformation("User logged out from all devices: {UserId}", userId);
            return Ok(new { Message = "Logged out from all devices successfully" });
        }

        /// <summary>
        /// Get current authenticated user information.
        /// </summary>
        [Authorize]
        [HttpGet("me")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> GetCurrentUser()
        {
            var userId = User.FindFirst("userId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { Message = "User not found" });

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                user.Id,
                user.Email,
                user.FullName,
                Roles = roles,
                user.CreatedAt,
                user.LastLoginAt
            });
        }

        /// <summary>
        /// Change password for authenticated user.
        /// </summary>
        [Authorize]
        [HttpPost("change-password")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userId = User.FindFirst("userId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { Message = "User not found" });

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed password change for user {UserId}: {Errors}", 
                    userId, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
            }

            _logger.LogInformation("Password changed for user {UserId}", userId);

            // Revoke all tokens to force re-login
            await _jwtTokenService.RevokeAllTokensAsync(userId);

            return Ok(new { Message = "Password changed successfully. Please login again." });
        }
    }

    public class ChangePasswordRequest
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
}
