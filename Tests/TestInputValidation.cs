using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

[TestFixture]
public sealed class TestInputValidation
{
    private const string AdminUsername = "test-admin";
    private const string AdminPassword = "Test-admin-password-123!";
    private SafeVaultApplicationFactory _factory = null!;
    private HttpClient _client = null!;
    private int _adminUserId;

    [OneTimeSetUp]
    public async Task SetUp()
    {
        _factory = new SafeVaultApplicationFactory();
        _client = _factory.CreateClient();

        var adminLogin = await LoginAsync(_client, AdminUsername, AdminPassword);
        _adminUserId = adminLogin.User.UserId;
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", adminLogin.AccessToken);
    }

    [OneTimeTearDown]
    public void TearDown()
    {
        _client.Dispose();
        _factory.Dispose();
        _factory.DeleteDatabase();
    }

    [Test]
    public async Task SqlInjectionPayloadPassedToStoreIsBoundAsData()
    {
        const string injectedUsername = "x'); DROP TABLE Users;--";
        var userStore = _factory.Services.GetRequiredService<IUserStore>();

        var existingUser = await userStore.CreateAsync(
            "existing-user",
            "existing@example.com",
            "existing-password-hash",
            CancellationToken.None);
        var injectedUser = await userStore.CreateAsync(
            injectedUsername,
            "attacker@example.com",
            "injected-password-hash",
            CancellationToken.None);

        var response = await _client.GetAsync($"/users/{injectedUser.UserId}");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var fetched = await response.Content.ReadFromJsonAsync<UserResponse>();
        Assert.That(fetched!.Username, Is.EqualTo(injectedUsername));

        var existingResponse = await _client.GetAsync($"/users/{existingUser.UserId}");
        Assert.That(existingResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task SqlInjectionCharactersAreSanitizedBeforePersistence()
    {
        const string injectedUsername = "x'); DROP TABLE Users;--";

        var response = await SubmitAsync(injectedUsername, "attacker@example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        var created = await ReadUserAsync(response);

        var fetchResponse = await _client.GetAsync($"/users/{created.UserId}");
        Assert.That(fetchResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var fetched = await fetchResponse.Content.ReadFromJsonAsync<UserResponse>();
        Assert.That(created.Username, Is.EqualTo("x DROP TABLE Users--"));
        Assert.That(fetched!.Username, Is.EqualTo(created.Username));
    }

    [Test]
    public async Task XssPayloadIsReturnedAsEncodedJsonText()
    {
        const string xssUsername = "<script>alert(1)</script>";

        var response = await SubmitAsync(xssUsername, "xss@example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/json"));

        var json = await response.Content.ReadAsStringAsync();
        Assert.That(json, Does.Not.Contain(xssUsername));
        Assert.That(json, Does.Not.Contain("<"));

        using var document = JsonDocument.Parse(json);
        Assert.That(document.RootElement.GetProperty("username").GetString(), Is.EqualTo("scriptalert1script"));
    }

    [Test]
    public async Task InvalidEmailIsRejectedWithoutCreatingAUser()
    {
        var response = await SubmitAsync("valid-user", "not-an-email");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/problem+json"));
    }

    [Test]
    public async Task LoginVerifiesPasswordAndReturnsShortLivedBearerToken()
    {
        const string username = "login-user";
        const string password = "User-password-123!";
        var registration = await SubmitAsync(username, "login@example.com", password);
        Assert.That(registration.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        var registeredUser = await ReadUserAsync(registration);

        var storedUser = await _factory.Services.GetRequiredService<IUserStore>()
            .GetByUsernameAsync(username, CancellationToken.None);
        Assert.That(storedUser!.PasswordHash, Is.Not.EqualTo(password));
        Assert.That(storedUser.Role, Is.EqualTo("User"));

        var login = await LoginAsync(_client, username, password);
        Assert.That(login.TokenType, Is.EqualTo("Bearer"));
        Assert.That(login.ExpiresAtUtc, Is.GreaterThan(DateTimeOffset.UtcNow));
        Assert.That(login.User.UserId, Is.EqualTo(registeredUser.UserId));

        using var userClient = CreateAuthenticatedClient(login.AccessToken);
        var ownProfile = await userClient.GetAsync($"/users/{registeredUser.UserId}");
        Assert.That(ownProfile.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task InvalidPasswordDoesNotAuthenticate()
    {
        const string username = "invalid-login-user";
        var registration = await SubmitAsync(username, "invalid-login@example.com", "User-password-123!");
        Assert.That(registration.StatusCode, Is.EqualTo(HttpStatusCode.Created));

        using var anonymousClient = _factory.CreateClient();
        var response = await anonymousClient.PostAsJsonAsync("/auth/login", new LoginRequest
        {
            Username = username,
            Password = "Wrong-password-123!"
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminFeatureRequiresAdminRoleAndUserCannotReadAnotherProfile()
    {
        const string username = "regular-user";
        const string password = "Regular-user-password-123!";
        var registration = await SubmitAsync(username, "regular@example.com", password);
        Assert.That(registration.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        var regularUser = await ReadUserAsync(registration);
        var regularLogin = await LoginAsync(_client, username, password);

        using var regularClient = CreateAuthenticatedClient(regularLogin.AccessToken);
        var adminListResponse = await regularClient.GetAsync("/admin/users");
        Assert.That(adminListResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));

        var otherProfileResponse = await regularClient.GetAsync($"/users/{_adminUserId}");
        Assert.That(otherProfileResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));

        var adminList = await _client.GetAsync("/admin/users");
        Assert.That(adminList.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        using var anonymousClient = _factory.CreateClient();
        var anonymousResponse = await anonymousClient.GetAsync("/admin/users");
        Assert.That(anonymousResponse.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(regularUser.UserId, Is.Not.EqualTo(_adminUserId));
    }

    private async Task<HttpResponseMessage> SubmitAsync(string username, string email) =>
        await SubmitAsync(username, email, "Test-user-password-123!");

    private async Task<HttpResponseMessage> SubmitAsync(string username, string email, string password) =>
        await _client.PostAsync("/submit", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = username,
            ["email"] = email,
            ["password"] = password
        }));

    private static async Task<LoginResponse> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/auth/login", new LoginRequest
        {
            Username = username,
            Password = password
        });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<LoginResponse>())!;
    }

    private HttpClient CreateAuthenticatedClient(string token)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task<UserResponse> ReadUserAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        return new UserResponse(
            document.RootElement.GetProperty("userId").GetInt32(),
            document.RootElement.GetProperty("username").GetString()!,
            document.RootElement.GetProperty("email").GetString()!);
    }

    private sealed class SafeVaultApplicationFactory : WebApplicationFactory<Program>
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"safevault-tests-{Guid.NewGuid():N}.db");

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("ConnectionStrings:SafeVault", $"Data Source={_databasePath};Pooling=False");
            builder.UseSetting(
                "Authentication:Jwt:SigningKey",
                "test-signing-key-with-at-least-thirty-two-bytes");
            builder.UseSetting("Authentication:Jwt:Issuer", "SafeVault.Test");
            builder.UseSetting("Authentication:Jwt:Audience", "SafeVault.Tests");
            builder.UseSetting("SafeVault:BootstrapAdmin:Username", AdminUsername);
            builder.UseSetting("SafeVault:BootstrapAdmin:Email", "test-admin@example.com");
            builder.UseSetting("SafeVault:BootstrapAdmin:Password", AdminPassword);
        }

        public void DeleteDatabase()
        {
            if (File.Exists(_databasePath))
                File.Delete(_databasePath);
        }
    }
}
