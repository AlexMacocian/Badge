using Badge.Options;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Data.SQLite;
using System.Extensions;

namespace Badge.Services.Database;

public abstract class SqliteTableBase<TOptions> : IDisposable
    where TOptions : class, IDatabaseOptions, new()
{
    public const string DateTimeFormat = "yyyy-MM-dd HH:mm:ss.fff";

    private static readonly SemaphoreSlim Semaphore = new(1);
    private static bool TableInitialized;

    private readonly TOptions databaseOptions;
    private readonly SQLiteConnection connection;
    private readonly ILogger logger;

    protected abstract string TableDefinition { get; }

    public SqliteTableBase(
        IOptions<TOptions> options,
        SQLiteConnection sQLiteConnection,
        ILogger logger)
    {
        this.databaseOptions = options.ThrowIfNull().Value;
        this.connection = sQLiteConnection.ThrowIfNull();
        this.logger = logger.ThrowIfNull();

        if (this.databaseOptions.TableName is null)
        {
            throw new InvalidOperationException("TableName cannot be null");
        }
    }

    protected async Task<SQLiteCommandWrapper> GetCommand(string query, CancellationToken cancellationToken)
    {
        if (this.connection.State == System.Data.ConnectionState.Closed)
        {
            await this.connection.OpenAsync(cancellationToken);
        }

        if (!TableInitialized)
        {
            using var context = await Semaphore.Acquire();
            if (!TableInitialized)
            {
                await EnsureTableExists(cancellationToken);
                TableInitialized = true;
            }
        }

        var command = new SQLiteCommand(query, this.connection);
        return new SQLiteCommandWrapper(command, this.databaseOptions.TableName!, this.logger);
    }

    public void Dispose()
    {
        this.connection.Dispose();
    }

    private async Task EnsureTableExists(CancellationToken cancellationToken)
    {
        var tableQuery = $"CREATE TABLE IF NOT EXISTS {this.databaseOptions.TableName} ({this.TableDefinition});";
        using var command = new SQLiteCommand(tableQuery, this.connection);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
