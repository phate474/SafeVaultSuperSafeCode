/// <summary>A short-lived bearer token and the authenticated user.</summary>
public sealed record LoginResponse(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAtUtc,
    UserResponse User);
