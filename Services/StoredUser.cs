public sealed record StoredUser(
    int UserId,
    string Username,
    string Email,
    string? PasswordHash,
    string Role);
