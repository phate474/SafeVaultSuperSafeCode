using System.ComponentModel.DataAnnotations;

/// <summary>Form data used to create a SafeVault user.</summary>
public sealed record CreateUserRequest
{
    [Required, StringLength(100)]
    public required string Username { get; init; }

    [Required, EmailAddress, StringLength(254)]
    public required string Email { get; init; }
}
