using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public sealed class JwtTokenService(
    string signingKey,
    string issuer,
    string audience,
    TimeSpan tokenLifetime)
{
    private readonly SymmetricSecurityKey _signingKey =
        new(Encoding.UTF8.GetBytes(signingKey));

    public LoginResponse CreateToken(StoredUser user)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.Add(tokenLifetime);
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim("role", user.Role)
        };
        var token = new JwtSecurityToken(
            issuer,
            audience,
            claims,
            now.UtcDateTime,
            expiresAt.UtcDateTime,
            new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256));

        return new LoginResponse(
            new JwtSecurityTokenHandler().WriteToken(token),
            "Bearer",
            expiresAt,
            new UserResponse(user.UserId, user.Username, user.Email));
    }
}
