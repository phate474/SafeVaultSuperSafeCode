using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using NUnit.Framework;

[TestFixture]
public sealed class TestInputValidation
{
    private SafeVaultApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    [OneTimeSetUp]
    public void SetUp()
    {
        _factory = new SafeVaultApplicationFactory();
        _client = _factory.CreateClient();
    }

    [OneTimeTearDown]
    public void TearDown()
    {
        _client.Dispose();
        _factory.Dispose();
        _factory.DeleteDatabase();
    }

    [Test]
    public async Task SqlInjectionPayloadIsStoredAsDataAndDoesNotBreakQueries()
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

    private async Task<HttpResponseMessage> SubmitAsync(string username, string email) =>
        await _client.PostAsync("/submit", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = username,
            ["email"] = email
        }));

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

        protected override void ConfigureWebHost(IWebHostBuilder builder) =>
            builder.UseSetting("ConnectionStrings:SafeVault", $"Data Source={_databasePath};Pooling=False");

        public void DeleteDatabase()
        {
            if (File.Exists(_databasePath))
                File.Delete(_databasePath);
        }
    }
}
