namespace SafeVault.Models.DTOs
{
    /// <summary>
    /// Response returned after successful authentication.
    /// </summary>
    public class AuthenticationResponse
    {
        /// <summary>
        /// JWT access token for API authorization.
        /// </summary>
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// Refresh token for obtaining new access tokens.
        /// </summary>
        public string RefreshToken { get; set; } = string.Empty;

        /// <summary>
        /// User ID.
        /// </summary>
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// User's email.
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// User's full name.
        /// </summary>
        public string? FullName { get; set; }

        /// <summary>
        /// User's roles.
        /// </summary>
        public IList<string> Roles { get; set; } = new List<string>();

        /// <summary>
        /// Access token expiration time (UTC).
        /// </summary>
        public DateTime ExpiresAt { get; set; }
    }
}
