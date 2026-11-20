using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http.HttpResults;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this WebApplication app)
    {
        app.MapPost("/submit", async Task<Results<Created<UserResponse>, ValidationProblem>> (
            HttpRequest httpRequest,
            IUserStore userStore,
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
                Username = form["username"].ToString().Trim(),
                Email = form["email"].ToString().Trim()
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

            if (request.Username.Any(char.IsControl) || request.Email.Any(char.IsControl))
            {
                return TypedResults.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["input"] = ["Control characters are not allowed."]
                });
            }

            var user = await userStore.CreateAsync(request.Username, request.Email, cancellationToken);
            return TypedResults.Created($"/users/{user.UserId}", user);
        })
        .WithName("CreateUser")
        .WithSummary("Create a user from submitted form data")
        .WithDescription("Validates submitted fields and stores them using parameterized SQL.")
        .Accepts<CreateUserRequest>("application/x-www-form-urlencoded")
        .Produces<UserResponse>(StatusCodes.Status201Created)
        .ProducesValidationProblem();

        app.MapGet("/users/{userId:int}", async Task<Results<Ok<UserResponse>, NotFound>> (
            int userId,
            IUserStore userStore,
            CancellationToken cancellationToken) =>
        {
            var user = await userStore.GetByIdAsync(userId, cancellationToken);
            return user is null ? TypedResults.NotFound() : TypedResults.Ok(user);
        })
        .WithName("GetUserById")
        .WithSummary("Get a user by ID")
        .WithDescription("Returns a user record as JSON.")
        .Produces<UserResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound);
    }

    private static Dictionary<string, string[]> ToErrors(IEnumerable<ValidationResult> validationResults) =>
        validationResults
            .SelectMany(result => result.MemberNames.DefaultIfEmpty(string.Empty)
                .Select(member => (Member: member, Error: result.ErrorMessage ?? "Invalid value.")))
            .GroupBy(item => item.Member)
            .ToDictionary(group => group.Key, group => group.Select(item => item.Error).ToArray());
}
