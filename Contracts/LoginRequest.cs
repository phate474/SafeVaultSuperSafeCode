using System.ComponentModel.DataAnnotations;

/// <summary>Credentials submitted to obtain an access token.</summary>
public sealed record LoginRequest
{
    [Required, StringLength(100)]
    public required string Username { get; init; }

    [Required, StringLength(128)]
    public required string Password { get; init; }
}
