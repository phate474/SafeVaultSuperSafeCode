using System.Text.Encodings.Web;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddValidation();
builder.Services.AddProblemDetails();
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Encoder = JavaScriptEncoder.Default
);
builder.Services.AddSingleton<IUserStore>(_ => new SqliteUserStore(
    builder.Configuration.GetConnectionString("SafeVault")
        ?? throw new InvalidOperationException("The SafeVault connection string is not configured.")
));
builder.Services.AddSingleton<IPasswordHasher<StoredUser>, PasswordHasher<StoredUser>>();
builder.Services.AddSingleton<IUserAccountService, UserAccountService>();

var signingKey = builder.Configuration["Authentication:Jwt:SigningKey"];
if (string.IsNullOrWhiteSpace(signingKey) || Encoding.UTF8.GetByteCount(signingKey) < 32)
{
    throw new InvalidOperationException(
        "Configure Authentication:Jwt:SigningKey with a secret of at least 32 UTF-8 bytes.");
}

var issuer = builder.Configuration["Authentication:Jwt:Issuer"] ?? "SafeVault";
var audience = builder.Configuration["Authentication:Jwt:Audience"] ?? "SafeVault.Client";
var tokenLifetime = TimeSpan.FromMinutes(15);
builder.Services.AddSingleton(new JwtTokenService(signingKey, issuer, audience, tokenLifetime));
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "unique_name",
            RoleClaimType = "role"
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

var userStore = app.Services.GetRequiredService<IUserStore>();
await userStore.InitializeAsync();

var bootstrapUsername = builder.Configuration["SafeVault:BootstrapAdmin:Username"];
var bootstrapEmail = builder.Configuration["SafeVault:BootstrapAdmin:Email"];
var bootstrapPassword = builder.Configuration["SafeVault:BootstrapAdmin:Password"];
var bootstrapValues = new[] { bootstrapUsername, bootstrapEmail, bootstrapPassword };
if (bootstrapValues.Any(value => !string.IsNullOrEmpty(value)))
{
    if (bootstrapValues.Any(string.IsNullOrEmpty))
        throw new InvalidOperationException("All SafeVault bootstrap administrator settings must be provided together.");

    await app.Services.GetRequiredService<IUserAccountService>().EnsureBootstrapAdminAsync(
        bootstrapUsername!,
        bootstrapEmail!,
        bootstrapPassword!,
        CancellationToken.None);
}

app.MapUserEndpoints();

app.Run();

public partial class Program { }
