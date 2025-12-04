using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models.DTOs
{
    /// <summary>
    /// Request model for user registration.
    /// </summary>
    public class RegisterRequest
    {
        /// <summary>
        /// User's email address.
        /// </summary>
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// User's password.
        /// </summary>
        [Required(ErrorMessage = "Password is required")]
        [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$",
            ErrorMessage = "Password must contain uppercase, lowercase, digit, and special character")]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Password confirmation.
        /// </summary>
        [Required(ErrorMessage = "Password confirmation is required")]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;

        /// <summary>
        /// User's full name.
        /// </summary>
        [Required(ErrorMessage = "Full name is required")]
        [StringLength(100, MinimumLength = 2, ErrorMessage = "Full name must be between 2 and 100 characters")]
        [RegularExpression(@"^[a-zA-Z\s\-'.]+$", ErrorMessage = "Full name can only contain letters, spaces, hyphens, apostrophes, and periods")]
        public string FullName { get; set; } = string.Empty;
    }
}
