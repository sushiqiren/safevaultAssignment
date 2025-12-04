# SafeVault - Secure Web Application

SafeVault is a secure web application demonstrating best practices for handling sensitive data with proper input validation, SQL injection prevention, secure authentication with BCrypt password hashing, and Role-Based Access Control (RBAC).

## Features

### 🔒 Security Features

1. **Input Validation**
   - Client-side validation in HTML/JavaScript
   - Server-side validation in C#
   - Protection against XSS attacks
   - Protection against SQL injection
   - Protection against path traversal attacks

2. **Parameterized Queries**
   - All database operations use Entity Framework with parameterized queries
   - No raw SQL concatenation
   - Protection against SQL injection attacks

3. **Input Sanitization**
   - HTML encoding to prevent XSS
   - Removal of malicious characters
   - Pattern matching for dangerous inputs

4. **Secure Authentication**
   - BCrypt password hashing with work factor 12 (4,096 iterations)
   - Account lockout after 5 failed attempts (15-minute duration)
   - Password strength validation (8+ chars, uppercase, lowercase, digit, special char)
   - Secure password change functionality

5. **Role-Based Access Control (RBAC)**
   - Three user roles: User, Admin, Moderator
   - Custom `[AuthorizeRole]` attribute for endpoint protection
   - Admin dashboard for user management
   - Role-based UI redirects
   - Self-protection mechanisms (admins cannot modify own privileges)

## User Roles

| Role | Description | Dashboard Access | Permissions |
|------|-------------|------------------|-------------|
| **User** | Default role | ❌ No | Basic access, own data only |
| **Moderator** | Elevated permissions | ❌ No | View all users (read-only) |
| **Admin** | Full system access | ✅ Yes | User management, statistics, all features |

## Project Structure

```
SafeVault/
├── Attributes/
│   └── AuthorizeRoleAttribute.cs   # RBAC authorization filter
├── Controllers/
│   ├── AdminController.cs          # Admin-only endpoints (NEW)
│   ├── AuthController.cs           # Authentication endpoints
│   └── UsersController.cs          # User API endpoints
├── Data/
│   └── SafeVaultDbContext.cs       # Database context configuration
├── Database/
│   └── database.sql                # Database schema
├── Models/
│   ├── User.cs                     # User entity (with Role property)
│   ├── UserRole.cs                 # Role enumeration (NEW)
│   ├── LoginDto.cs                 # Login data transfer object
│   ├── RegisterDto.cs              # Registration DTO
│   └── UserSubmissionDto.cs        # User submission DTO
├── Services/
│   ├── AuthenticationService.cs    # BCrypt hashing & authentication
│   └── InputValidationService.cs   # Input validation and sanitization
├── Tests/
│   ├── TestAuthentication.cs       # Authentication tests (20 tests)
│   ├── TestInputValidation.cs      # Security tests (21 tests)
│   └── TestRBAC.cs                 # RBAC tests (16 tests) (NEW)
├── wwwroot/
│   ├── admin.html                  # Admin dashboard (NEW)
│   ├── login.html                  # Login page with role redirect
│   └── webform.html                # Standard user interface
├── Program.cs                      # Application configuration
├── SafeVault.csproj               # Project dependencies
├── AUTHENTICATION_GUIDE.md         # Authentication documentation
├── RBAC_GUIDE.md                   # RBAC full documentation (NEW)
├── RBAC_QUICK_REFERENCE.md         # RBAC quick reference (NEW)
└── TEST_RESULTS.md                 # Test results documentation

```

## Getting Started

### Prerequisites

- .NET 9.0 SDK
- SQL Server (or use in-memory database for development)

### Installation

1. **Restore dependencies**
   ```powershell
   dotnet restore
   ```

2. **Build the project**
   ```powershell
   dotnet build
   ```

3. **Run the application**
   ```powershell
   dotnet run
   ```

4. **Access the application**
   - **Login Page**: `https://localhost:5001/login.html` (Start here)
   - **Admin Dashboard**: `https://localhost:5001/admin.html` (Admin role required)
   - **User Interface**: `https://localhost:5001/webform.html` (All authenticated users)
   - **Swagger API**: `https://localhost:5001/swagger`

5. **Create First Admin User** (Required for dashboard access)
   
   After registration, manually update the database to grant admin role:
   ```sql
   UPDATE Users SET Role = 1 WHERE Username = 'your_username';
   ```
   
   Or use SQL insert directly:
   ```sql
   INSERT INTO Users (Username, Email, PasswordHash, Role, CreatedAt, UpdatedAt)
   VALUES ('admin', 'admin@safevault.com', 'hashed_password_here', 1, GETDATE(), GETDATE());
   ```

### Running Tests

Run all 57 security, authentication, and RBAC tests:

```powershell
dotnet test
```

**Test Results:**
- 21 Input Validation & Security Tests
- 20 Authentication Tests (BCrypt, password strength, lockout)
- 16 RBAC Tests (role management, authorization)
- **Total: 57 tests, 100% passing**

## API Endpoints

### Authentication Endpoints (Public)

#### POST `/api/auth/register`
Register a new user account.

**Request Body:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### POST `/api/auth/login`
Authenticate user and receive role information.

**Request Body:**
```json
{
  "username": "john_doe",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "message": "Login successful!",
  "user": {
    "userId": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "role": "User",
    "lastLogin": "2025-12-03T15:30:00Z"
  }
}
```

### User Endpoints (Authenticated Users)

#### GET `/api/users/{id}`
Get user by ID (parameterized query).

#### PUT `/api/users/{id}`
Update user information.

#### POST `/api/auth/{userId}/change-password`
Change user password (requires current password).

### Admin Endpoints (Admin Role Required)

⚠️ **All admin endpoints require `X-User-Id` and `X-User-Role: Admin` headers**

#### GET `/api/admin/users`
Get all users with detailed information.

#### GET `/api/admin/statistics`
Get system statistics (user counts, locked accounts, recent logins).

#### PUT `/api/admin/users/{userId}/role`
Change user role (User/Moderator/Admin).

#### POST `/api/admin/users/{userId}/unlock`
Unlock a locked user account.

#### DELETE `/api/admin/users/{userId}`
Delete a user account.

#### POST `/api/admin/users/{userId}/reset-password`
Reset user password (admin override).

### Moderator Endpoints (Moderator or Admin)

#### GET `/api/users`
Get all users (read-only access).

## Security Implementation

### Step 1: Input Validation

The `InputValidationService` provides comprehensive validation:

- **Username Validation**: 3-50 characters, alphanumeric and underscores only
- **Email Validation**: Proper email format, max 100 characters
- **Pattern Detection**: Identifies SQL injection, XSS, and other attacks
- **Sanitization**: HTML encoding and character filtering

### Step 2: Authentication & Password Security

The `AuthenticationService` implements secure authentication:

- **BCrypt Hashing**: Work factor 12 (4,096 iterations)
- **Password Strength**: Enforces uppercase, lowercase, digit, special character, 8+ chars
- **Account Lockout**: 5 failed attempts = 15-minute lockout
- **Audit Logging**: All authentication events logged

### Step 3: Role-Based Access Control

The `AuthorizeRoleAttribute` protects endpoints:

- **Role Verification**: Checks user role before controller execution
- **Header-Based Auth**: Uses `X-User-Id` and `X-User-Role` headers
- **403 Forbidden**: Returns clear error when role insufficient
- **Self-Protection**: Admins cannot modify own critical permissions

### Step 4: Parameterized Queries

All database operations use Entity Framework Core which automatically generates parameterized queries:

```csharp
// Example: Secure user lookup
var user = await _context.Users
    .Where(u => u.Username == sanitizedUsername)
    .FirstOrDefaultAsync();
```

This prevents SQL injection by ensuring user input is never concatenated into SQL strings.

## Testing

The comprehensive test suite includes **57 tests** across three categories:

### 1. Input Validation & Security (`TestInputValidation.cs`) - 21 Tests
- **SQL Injection Tests**: 7 test cases covering various injection patterns
- **XSS Tests**: 5 tests for script tags, event handlers, and JavaScript protocols
- **Valid Input Tests**: Ensures legitimate inputs are accepted
- **Edge Cases**: Boundary testing, special characters, empty inputs
- **Additional Security**: Path traversal and command injection tests

### 2. Authentication & Password Security (`TestAuthentication.cs`) - 20 Tests
- **Password Hashing**: BCrypt implementation verification
- **Password Verification**: Correct/incorrect password handling
- **Password Strength**: Validation of complexity requirements
- **Account Lockout**: Failed attempt tracking and lockout enforcement
- **Authentication Flow**: Login success/failure scenarios

### 3. Role-Based Access Control (`TestRBAC.cs`) - 16 Tests
- **User Role Management**: Role assignment and defaults
- **Admin Operations**: Statistics, user list, role changes
- **Account Management**: Unlock, delete, password reset
- **Authorization**: Self-protection mechanisms
- **Multi-Role Support**: Coexistence of different roles

### Test Execution

```powershell
# Run all tests
dotnet test

# Run specific test category
dotnet test --filter "TestRBAC"
dotnet test --filter "TestAuthentication"
dotnet test --filter "TestInputValidation"
```

**Expected Results:** 57 tests, 100% passing

## Documentation

- **[RBAC_GUIDE.md](RBAC_GUIDE.md)** - Complete RBAC implementation guide with API references
- **[RBAC_QUICK_REFERENCE.md](RBAC_QUICK_REFERENCE.md)** - Quick reference for common admin tasks
- **[AUTHENTICATION_GUIDE.md](AUTHENTICATION_GUIDE.md)** - BCrypt authentication implementation details
- **[TEST_RESULTS.md](TEST_RESULTS.md)** - Detailed test results and coverage

## Database Configuration

### Development
Uses in-memory database by default for easy testing.

### Production
Configure connection string in `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "SafeVaultConnection": "Server=your-server;Database=SafeVaultDb;..."
  }
}
```

Then run migrations:
```powershell
dotnet ef migrations add InitialCreate
dotnet ef database update
```

Or use the provided `database.sql` script.

## Best Practices Implemented

✅ Client-side and server-side validation  
✅ Input sanitization and HTML encoding  
✅ Parameterized queries (Entity Framework)  
✅ BCrypt password hashing (work factor 12)  
✅ Account lockout protection  
✅ Password strength enforcement  
✅ Role-Based Access Control (RBAC)  
✅ Admin dashboard with audit logging  
✅ Self-protection mechanisms  
✅ Proper error handling and logging  
✅ HTTPS enforcement  
✅ CORS configuration  
✅ Comprehensive security testing (57 tests)  
✅ Defense in depth approach  

## Security Checklist

- [x] Input validation on all user inputs
- [x] Parameterized queries for all database operations
- [x] XSS prevention through HTML encoding
- [x] SQL injection prevention
- [x] Path traversal protection
- [x] Command injection protection
- [x] Secure password hashing (BCrypt)
- [x] Account lockout after failed attempts
- [x] Password strength validation
- [x] Role-based authorization
- [x] Admin audit logging
- [x] Self-protection for privileged accounts
- [x] Comprehensive test coverage (57 tests)
- [x] Secure error handling
- [x] HTTPS enforcement
- [x] Security logging

## Admin Dashboard Features

The Admin Dashboard (`/admin.html`) provides:

- 📊 **Real-time Statistics**: User counts, locked accounts, recent logins
- 👥 **User Management**: View, edit, delete users
- 🔑 **Role Management**: Change user roles (User/Moderator/Admin)
- 🔓 **Account Recovery**: Unlock locked accounts
- 🔐 **Password Reset**: Admin-initiated password resets
- 📝 **Audit Logging**: All actions logged for security review

**Access:** Login with Admin role → Auto-redirects to dashboard

## Quick Start Guide

1. **Clone and Build**
   ```powershell
   git clone <repository>
   cd SafeVault
   dotnet build
   ```

2. **Run Tests** (Verify security)
   ```powershell
   dotnet test
   ```

3. **Start Application**
   ```powershell
   dotnet run
   ```

4. **Create Admin Account**
   - Register at `/login.html`
   - Update database: `UPDATE Users SET Role = 1 WHERE Username = 'your_username'`
   - Login again → Access admin dashboard

5. **Access Features**
   - **Admin Dashboard**: `https://localhost:5001/admin.html`
   - **User Interface**: `https://localhost:5001/webform.html`
   - **API Docs**: `https://localhost:5001/swagger`

## Technology Stack

- **Backend**: ASP.NET Core 9.0 (C#)
- **Database**: Entity Framework Core 9.0.5 (SQL Server / In-Memory)
- **Authentication**: BCrypt.Net-Next 4.0.3
- **Testing**: NUnit 4.3.0 (57 comprehensive tests)
- **API Documentation**: Swashbuckle.AspNetCore 7.2.0
- **Frontend**: HTML5, JavaScript, CSS3

## License

This project is for educational purposes demonstrating secure coding practices.

## Contributing

This is an educational project showcasing enterprise-level security implementations including:
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- Secure authentication with BCrypt
- Role-Based Access Control (RBAC)
- Admin dashboard and audit logging

Feel free to use it as a reference for implementing security best practices in your own applications.
