using Microsoft.AspNetCore.Identity;

namespace SafeVault.Models
{
    /// <summary>
    /// Extended IdentityUser with custom properties for SafeVault.
    /// Inherits all Identity features: password hashing, security stamps, etc.
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// User's full display name.
        /// </summary>
        public string? FullName { get; set; }

        /// <summary>
        /// Date when the user account was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Date when the user account was last updated.
        /// </summary>
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Last successful login timestamp.
        /// </summary>
        public DateTime? LastLoginAt { get; set; }

        /// <summary>
        /// Indicates if the user account is active.
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// Navigation property for refresh tokens.
        /// </summary>
        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }
}
