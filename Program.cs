using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Encoder = JavaScriptEncoder.Default
);
builder.Services.AddSingleton<IUserStore>(_ => new SqliteUserStore(
    builder.Configuration.GetConnectionString("SafeVault")
        ?? throw new InvalidOperationException("The SafeVault connection string is not configured.")
));

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

await app.Services.GetRequiredService<IUserStore>().InitializeAsync();
app.MapUserEndpoints();

app.Run();

public partial class Program { }
