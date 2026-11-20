public interface IUserStore
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
    Task<UserResponse> CreateAsync(
        string username,
        string email,
        string passwordHash,
        CancellationToken cancellationToken);
    Task<UserResponse?> GetByIdAsync(int userId, CancellationToken cancellationToken);
    Task<StoredUser?> GetByUsernameAsync(string username, CancellationToken cancellationToken);
    Task<StoredUser> CreateBootstrapAdminAsync(
        string username,
        string email,
        string passwordHash,
        CancellationToken cancellationToken);
    Task UpdatePasswordHashAsync(int userId, string passwordHash, CancellationToken cancellationToken);
    Task<IReadOnlyList<UserResponse>> GetAllAsync(CancellationToken cancellationToken);
}
