using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using BCrypt.Net;
using BC = BCrypt.Net.BCrypt;

public sealed class UserAccountService : IUserAccountService
{
    private const int BCryptWorkFactor = 11;
    private readonly IUserStore _userStore;
    private readonly IPasswordHasher<StoredUser> _legacyPasswordHasher;
    private readonly string _dummyPasswordHash;

    public UserAccountService(IUserStore userStore, IPasswordHasher<StoredUser> passwordHasher)
    {
        _userStore = userStore;
        _legacyPasswordHasher = passwordHasher;
        _dummyPasswordHash = HashPassword(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
    }

    public async Task<UserResponse> RegisterAsync(
        string username,
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        var passwordHash = HashPassword(password);
        return await _userStore.CreateAsync(username, email, passwordHash, cancellationToken);
    }

    public async Task<StoredUser?> ValidateCredentialsAsync(
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        var user = await _userStore.GetByUsernameAsync(username, cancellationToken);
        if (user?.PasswordHash is not { } passwordHash)
        {
            _ = BC.EnhancedVerify(password, _dummyPasswordHash, HashType.SHA384);
            return null;
        }

        if (passwordHash.StartsWith("$2", StringComparison.Ordinal))
        {
            return BC.EnhancedVerify(password, passwordHash, HashType.SHA384) ? user : null;
        }

        var legacyResult = _legacyPasswordHasher.VerifyHashedPassword(user, passwordHash, password);
        if (legacyResult == PasswordVerificationResult.Failed)
            return null;

        var upgradedHash = HashPassword(password);
        await _userStore.UpdatePasswordHashAsync(user.UserId, upgradedHash, cancellationToken);
        return user with { PasswordHash = upgradedHash };
    }

    public async Task EnsureBootstrapAdminAsync(
        string username,
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        var sanitizedUsername = SanitizeUsername(username).Trim();
        if (!string.Equals(username, sanitizedUsername, StringComparison.Ordinal) ||
            username.Length is 0 or > 100)
        {
            throw new InvalidOperationException("The bootstrap administrator username is invalid.");
        }

        if (!new EmailAddressAttribute().IsValid(email) || email.Length > 254)
            throw new InvalidOperationException("The bootstrap administrator email is invalid.");

        if (password.Length is < 12 or > 128)
            throw new InvalidOperationException("The bootstrap administrator password must be 12 to 128 characters.");

        var passwordHash = HashPassword(password);
        await _userStore.CreateBootstrapAdminAsync(username, email, passwordHash, cancellationToken);
    }

    private static string HashPassword(string password) =>
        BC.EnhancedHashPassword(
            password,
            BCryptWorkFactor,
            HashType.SHA384);

    private static string SanitizeUsername(string username) =>
        string.Concat(username.Where(character =>
            char.IsLetterOrDigit(character) || character is ' ' or '.' or '_' or '-'));
}
