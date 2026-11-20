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
                Username TEXT NOT NULL COLLATE NOCASE CHECK(length(Username) <= 100),
                Email TEXT NOT NULL CHECK(length(Email) <= 254),
                PasswordHash TEXT NULL,
                Role TEXT NOT NULL DEFAULT 'User' CHECK(Role IN ('User', 'Admin'))
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);

        var columns = await GetColumnNamesAsync(connection, cancellationToken);
        if (!columns.Contains("PasswordHash"))
            await ExecuteNonQueryAsync(connection, "ALTER TABLE Users ADD COLUMN PasswordHash TEXT NULL;", cancellationToken);
        if (!columns.Contains("Role"))
            await ExecuteNonQueryAsync(
                connection,
                "ALTER TABLE Users ADD COLUMN Role TEXT NOT NULL DEFAULT 'User';",
                cancellationToken);

        await ExecuteNonQueryAsync(
            connection,
            "CREATE UNIQUE INDEX IF NOT EXISTS IX_Users_Username ON Users (Username COLLATE NOCASE);",
            cancellationToken);
    }

    public async Task<UserResponse> CreateAsync(
        string username,
        string email,
        string passwordHash,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES ($username, $email, $passwordHash, 'User');
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$passwordHash", passwordHash);

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

    public async Task<StoredUser?> GetByUsernameAsync(
        string username,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, Email, PasswordHash, Role
            FROM Users
            WHERE Username = $username
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$username", username);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? ReadStoredUser(reader)
            : null;
    }

    public async Task<StoredUser> CreateBootstrapAdminAsync(
        string username,
        string email,
        string passwordHash,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                INSERT OR IGNORE INTO Users (Username, Email, PasswordHash, Role)
                VALUES ($username, $email, $passwordHash, 'Admin');
                """;
            command.Parameters.AddWithValue("$username", username);
            command.Parameters.AddWithValue("$email", email);
            command.Parameters.AddWithValue("$passwordHash", passwordHash);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var admin = await GetByUsernameAsync(username, cancellationToken)
            ?? throw new InvalidOperationException("The bootstrap administrator could not be loaded.");
        if (admin.Role != "Admin")
            throw new InvalidOperationException(
                "The configured bootstrap username already belongs to a non-administrator account.");

        return admin;
    }

    public async Task UpdatePasswordHashAsync(
        int userId,
        string passwordHash,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET PasswordHash = $passwordHash WHERE UserID = $userId;";
        command.Parameters.AddWithValue("$passwordHash", passwordHash);
        command.Parameters.AddWithValue("$userId", userId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<UserResponse>> GetAllAsync(CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users ORDER BY UserID;";

        var users = new List<UserResponse>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            users.Add(new UserResponse(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2)));
        }

        return users;
    }

    private static StoredUser ReadStoredUser(SqliteDataReader reader) =>
        new(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3),
            reader.GetString(4));

    private static async Task<HashSet<string>> GetColumnNamesAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA table_info(Users);";

        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            columns.Add(reader.GetString(1));

        return columns;
    }

    private static async Task ExecuteNonQueryAsync(
        SqliteConnection connection,
        string commandText,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = commandText;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
