using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http.HttpResults;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this WebApplication app)
    {
        app.MapPost("/submit", async Task<Results<Created<UserResponse>, ValidationProblem>> (
            HttpRequest httpRequest,
            IUserAccountService userAccountService,
            CancellationToken cancellationToken) =>
        {
            if (!httpRequest.HasFormContentType)
            {
                return TypedResults.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["form"] = ["Expected form-encoded input."]
                });
            }

            var form = await httpRequest.ReadFormAsync(cancellationToken);
            var request = new CreateUserRequest
            {
                Username = SanitizeUsername(form["username"].ToString()).Trim(),
                Email = form["email"].ToString().Trim(),
                Password = form["password"].ToString()
            };

            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(
                    request,
                    new ValidationContext(request),
                    validationResults,
                    validateAllProperties: true))
            {
                return TypedResults.ValidationProblem(ToErrors(validationResults));
            }

            if (request.Email.Any(char.IsControl))
            {
                return TypedResults.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["email"] = ["Control characters are not allowed."]
                });
            }

            var user = await userAccountService.RegisterAsync(
                request.Username,
                request.Email,
                request.Password,
                cancellationToken);
            return TypedResults.Created($"/users/{user.UserId}", user);
        })
        .AllowAnonymous()
        .WithName("CreateUser")
        .WithSummary("Register a user")
        .WithDescription("Validates form fields and stores a one-way password hash.")
        .Accepts<CreateUserRequest>("application/x-www-form-urlencoded")
        .Produces<UserResponse>(StatusCodes.Status201Created)
        .ProducesValidationProblem();

        app.MapPost("/auth/login", async Task<Results<Ok<LoginResponse>, UnauthorizedHttpResult>> (
            LoginRequest request,
            IUserAccountService userAccountService,
            JwtTokenService tokenService,
            CancellationToken cancellationToken) =>
        {
            var normalizedUsername = SanitizeUsername(request.Username).Trim();
            if (!string.Equals(normalizedUsername, request.Username.Trim(), StringComparison.Ordinal))
                return TypedResults.Unauthorized();

            var user = await userAccountService.ValidateCredentialsAsync(
                normalizedUsername,
                request.Password,
                cancellationToken);
            return user is null
                ? TypedResults.Unauthorized()
                : TypedResults.Ok(tokenService.CreateToken(user));
        })
        .AllowAnonymous()
        .WithName("Login")
        .WithSummary("Authenticate and issue a bearer token")
        .WithDescription("Returns a short-lived JWT when the supplied credentials are valid.")
        .Produces<LoginResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized)
        .ProducesValidationProblem();

        app.MapGet("/users/{userId:int}", async Task<Results<Ok<UserResponse>, NotFound, ForbidHttpResult>> (
            int userId,
            IUserStore userStore,
            System.Security.Claims.ClaimsPrincipal principal,
            CancellationToken cancellationToken) =>
        {
            if (!principal.IsInRole("Admin") &&
                !string.Equals(
                    principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value,
                    userId.ToString(CultureInfo.InvariantCulture),
                    StringComparison.Ordinal))
            {
                return TypedResults.Forbid();
            }

            var user = await userStore.GetByIdAsync(userId, cancellationToken);
            return user is null ? TypedResults.NotFound() : TypedResults.Ok(user);
        })
        .RequireAuthorization()
        .WithName("GetUserById")
        .WithSummary("Get a user by ID")
        .WithDescription("Returns a user record to its owner or an administrator.")
        .Produces<UserResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status403Forbidden);

        app.MapGet("/admin/users", async Task<Ok<IReadOnlyList<UserResponse>>> (
            IUserStore userStore,
            CancellationToken cancellationToken) =>
                TypedResults.Ok(await userStore.GetAllAsync(cancellationToken)))
            .RequireAuthorization(policy => policy.RequireRole("Admin"))
            .WithName("GetAllUsersForAdministrators")
            .WithSummary("List users for administrators")
            .WithDescription("Returns user profile data without password hashes.")
            .Produces<IReadOnlyList<UserResponse>>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);
    }

    private static Dictionary<string, string[]> ToErrors(IEnumerable<ValidationResult> validationResults) =>
        validationResults
            .SelectMany(result => result.MemberNames.DefaultIfEmpty(string.Empty)
                .Select(member => (Member: member, Error: result.ErrorMessage ?? "Invalid value.")))
            .GroupBy(item => item.Member)
            .ToDictionary(group => group.Key, group => group.Select(item => item.Error).ToArray());

    private static string SanitizeUsername(string username) =>
        string.Concat(username.Where(character =>
            char.IsLetterOrDigit(character) || character is ' ' or '.' or '_' or '-'));
}
