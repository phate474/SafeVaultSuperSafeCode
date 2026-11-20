public interface IUserStore
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
    Task<UserResponse> CreateAsync(string username, string email, CancellationToken cancellationToken);
    Task<UserResponse?> GetByIdAsync(int userId, CancellationToken cancellationToken);
}
