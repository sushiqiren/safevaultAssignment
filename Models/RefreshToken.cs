using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models
{
    /// <summary>
    /// Represents a refresh token for JWT authentication.
    /// Allows users to obtain new access tokens without re-authenticating.
    /// </summary>
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// The actual refresh token string (hashed).
        /// </summary>
        [Required]
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// JWT ID (jti) claim from the access token this refresh token is associated with.
        /// </summary>
        [Required]
        public string JwtId { get; set; } = string.Empty;

        /// <summary>
        /// Date and time when the token was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Date and time when the token expires.
        /// </summary>
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// Indicates whether the token has been used.
        /// </summary>
        public bool IsUsed { get; set; } = false;

        /// <summary>
        /// Indicates whether the token has been revoked/invalidated.
        /// </summary>
        public bool IsRevoked { get; set; } = false;

        /// <summary>
        /// Foreign key to ApplicationUser.
        /// </summary>
        [Required]
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// Navigation property to user.
        /// </summary>
        public virtual ApplicationUser? User { get; set; }
    }
}
