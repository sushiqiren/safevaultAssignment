using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models.DTOs
{
    /// <summary>
    /// Request model for refreshing access tokens.
    /// </summary>
    public class RefreshTokenRequest
    {
        /// <summary>
        /// Expired or expiring access token.
        /// </summary>
        [Required(ErrorMessage = "Access token is required")]
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// Valid refresh token.
        /// </summary>
        [Required(ErrorMessage = "Refresh token is required")]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
