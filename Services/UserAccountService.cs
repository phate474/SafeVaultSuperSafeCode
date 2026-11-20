using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

public sealed class UserAccountService : IUserAccountService
{
    private readonly IUserStore _userStore;
    private readonly IPasswordHasher<StoredUser> _passwordHasher;
    private readonly StoredUser _dummyUser;
    private readonly string _dummyPasswordHash;

    public UserAccountService(IUserStore userStore, IPasswordHasher<StoredUser> passwordHasher)
    {
        _userStore = userStore;
        _passwordHasher = passwordHasher;
        _dummyUser = new StoredUser(0, string.Empty, string.Empty, null, "User");
        _dummyPasswordHash = passwordHasher.HashPassword(
            _dummyUser,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
    }

    public async Task<UserResponse> RegisterAsync(
        string username,
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        var user = new StoredUser(0, username, email, null, "User");
        var passwordHash = _passwordHasher.HashPassword(user, password);
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
            _ = _passwordHasher.VerifyHashedPassword(_dummyUser, _dummyPasswordHash, password);
            return null;
        }

        var result = _passwordHasher.VerifyHashedPassword(user, passwordHash, password);
        if (result == PasswordVerificationResult.Failed)
            return null;

        if (result == PasswordVerificationResult.SuccessRehashNeeded)
        {
            var upgradedHash = _passwordHasher.HashPassword(user, password);
            await _userStore.UpdatePasswordHashAsync(user.UserId, upgradedHash, cancellationToken);
        }

        return user;
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

        var user = new StoredUser(0, username, email, null, "Admin");
        var passwordHash = _passwordHasher.HashPassword(user, password);
        await _userStore.CreateBootstrapAdminAsync(username, email, passwordHash, cancellationToken);
    }

    private static string SanitizeUsername(string username) =>
        string.Concat(username.Where(character =>
            char.IsLetterOrDigit(character) || character is ' ' or '.' or '_' or '-'));
}
