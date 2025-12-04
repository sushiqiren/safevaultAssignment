using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Models.DTOs;

namespace SafeVault.Services
{
    /// <summary>
    /// Service for generating and validating JWT tokens.
    /// </summary>
    public interface IJwtTokenService
    {
        Task<AuthenticationResponse> GenerateTokenAsync(ApplicationUser user);
        Task<AuthenticationResponse?> RefreshTokenAsync(RefreshTokenRequest request);
        Task<bool> RevokeTokenAsync(string userId, string refreshToken);
        Task<bool> RevokeAllTokensAsync(string userId);
    }

    public class JwtTokenService : IJwtTokenService
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<JwtTokenService> _logger;

        public JwtTokenService(
            IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext context,
            ILogger<JwtTokenService> logger)
        {
            _configuration = configuration;
            _userManager = userManager;
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// Generates access and refresh tokens for a user.
        /// </summary>
        public async Task<AuthenticationResponse> GenerateTokenAsync(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);
            var jwtId = Guid.NewGuid().ToString();

            // Generate access token
            var accessToken = GenerateAccessToken(user, roles, jwtId);
            var tokenHandler = new JwtSecurityTokenHandler();
            var accessTokenString = tokenHandler.WriteToken(accessToken);

            // Generate refresh token (plain text for user)
            var refreshToken = GenerateRefreshToken();
            
            // Hash the refresh token before storing in database
            var hashedRefreshToken = HashToken(refreshToken);
            
            var refreshTokenEntity = new RefreshToken
            {
                Token = hashedRefreshToken, // Store hashed version
                JwtId = jwtId,
                UserId = user.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                CreatedAt = DateTime.UtcNow
            };

            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Generated JWT tokens for user {UserId}", user.Id);

            return new AuthenticationResponse
            {
                AccessToken = accessTokenString,
                RefreshToken = refreshToken, // Return plain text to user
                UserId = user.Id,
                Email = user.Email!,
                FullName = user.FullName,
                Roles = roles,
                ExpiresAt = accessToken.ValidTo
            };
        }

        /// <summary>
        /// Validates refresh token and generates new access/refresh token pair.
        /// </summary>
        public async Task<AuthenticationResponse?> RefreshTokenAsync(RefreshTokenRequest request)
        {
            // Validate access token (without lifetime check)
            var principal = GetPrincipalFromExpiredToken(request.AccessToken);
            if (principal == null)
            {
                _logger.LogWarning("Invalid access token format");
                return null;
            }

            var jwtId = principal.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
            if (string.IsNullOrEmpty(jwtId))
            {
                _logger.LogWarning("Access token missing JTI claim");
                return null;
            }

            // Hash the incoming refresh token to compare with stored hash
            var hashedRefreshToken = HashToken(request.RefreshToken);

            // Find and validate refresh token
            var storedToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == hashedRefreshToken && rt.JwtId == jwtId);

            if (storedToken == null)
            {
                _logger.LogWarning("Refresh token not found or JTI mismatch");
                return null;
            }

            if (storedToken.IsUsed || storedToken.IsRevoked)
            {
                _logger.LogWarning("Refresh token already used or revoked for user {UserId}", storedToken.UserId);
                return null;
            }

            if (storedToken.ExpiresAt < DateTime.UtcNow)
            {
                _logger.LogWarning("Refresh token expired for user {UserId}", storedToken.UserId);
                return null;
            }

            // Mark old refresh token as used
            storedToken.IsUsed = true;
            await _context.SaveChangesAsync();

            // Generate new token pair
            var user = storedToken.User!;
            var response = await GenerateTokenAsync(user);

            _logger.LogInformation("Refreshed tokens for user {UserId}", user.Id);
            return response;
        }

        /// <summary>
        /// Revokes a specific refresh token.
        /// </summary>
        public async Task<bool> RevokeTokenAsync(string userId, string refreshToken)
        {
            var hashedToken = HashToken(refreshToken);
            var token = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.UserId == userId && rt.Token == hashedToken);

            if (token == null)
                return false;

            token.IsRevoked = true;
            await _context.SaveChangesAsync();

            _logger.LogInformation("Revoked refresh token for user {UserId}", userId);
            return true;
        }

        /// <summary>
        /// Revokes all refresh tokens for a user (logout from all devices).
        /// </summary>
        public async Task<bool> RevokeAllTokensAsync(string userId)
        {
            var tokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && !rt.IsRevoked)
                .ToListAsync();

            foreach (var token in tokens)
            {
                token.IsRevoked = true;
            }

            await _context.SaveChangesAsync();

            _logger.LogInformation("Revoked all refresh tokens for user {UserId}", userId);
            return true;
        }

        // Private helper methods

        private JwtSecurityToken GenerateAccessToken(ApplicationUser user, IList<string> roles, string jwtId)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                new Claim(JwtRegisteredClaimNames.Jti, jwtId),
                new Claim("userId", user.Id),
            };

            if (!string.IsNullOrEmpty(user.FullName))
            {
                claims.Add(new Claim("fullName", user.FullName));
            }

            // Add role claims
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not configured")));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15), // Short-lived access token
                signingCredentials: credentials
            );

            return token;
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, // Don't validate lifetime here
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                    _configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not configured")))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
                
                if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return null;
                }

                return principal;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");
                return null;
            }
        }

        /// <summary>
        /// Hashes a token using SHA256 for secure storage.
        /// </summary>
        private static string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }
}
