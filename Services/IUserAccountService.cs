public interface IUserAccountService
{
    Task<UserResponse> RegisterAsync(
        string username,
        string email,
        string password,
        CancellationToken cancellationToken);

    Task<StoredUser?> ValidateCredentialsAsync(
        string username,
        string password,
        CancellationToken cancellationToken);

    Task EnsureBootstrapAdminAsync(
        string username,
        string email,
        string password,
        CancellationToken cancellationToken);
}
