using Microsoft.Data.Sqlite;

public sealed class SqliteUserStore(string connectionString) : IUserStore
{
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL CHECK(length(Username) <= 100),
                Email TEXT NOT NULL CHECK(length(Email) <= 254)
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<UserResponse> CreateAsync(
        string username,
        string email,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email)
            VALUES ($username, $email);
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);

        var userId = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
        return new UserResponse(userId, username, email);
    }

    public async Task<UserResponse?> GetByIdAsync(int userId, CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, Email
            FROM Users
            WHERE UserID = $userId;
            """;
        command.Parameters.AddWithValue("$userId", userId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
            return null;

        return new UserResponse(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.GetString(2));
    }
}
