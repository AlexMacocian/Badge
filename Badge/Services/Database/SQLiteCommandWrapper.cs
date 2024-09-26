using System.Core.Extensions;
using System.Data.Common;
using System.Data.SQLite;
using System.Diagnostics;
using System.Extensions;
using System.Runtime.CompilerServices;

namespace Badge.Services.Database;

public sealed class SQLiteCommandWrapper(
    SQLiteCommand command, string tableName, ILogger logger) : IDisposable
{
    private readonly SQLiteCommand command = command.ThrowIfNull();
    private readonly string tableName = tableName.ThrowIfNull();
    private readonly ILogger logger = logger.ThrowIfNull();

    public SQLiteParameterCollection Parameters => this.command.Parameters;

    public async Task<int> ExecuteNonQuery(CancellationToken cancellationToken)
    {
        this.logger.LogInformation("[{fileName}] {tableName} << ExecuteNonQuery", this.command.Connection.FileName, this.tableName);
        var sw = Stopwatch.StartNew();
        var result = await this.command.ExecuteNonQueryAsync(cancellationToken);
        this.logger.LogInformation("[{fileName}] {tableName} >> {result} [{elapsedMillis} ms]", this.command.Connection.FileName, this.tableName, result, sw.ElapsedMilliseconds);
        return result;
    }

    public async IAsyncEnumerable<DbDataReader> ExecuteReader([EnumeratorCancellation]CancellationToken cancellationToken)
    {
        this.logger.LogInformation("[{fileName}] {tableName} << ExecuteReader", this.command.Connection.FileName, this.tableName);
        var sw = Stopwatch.StartNew();
        using var reader = await this.command.ExecuteReaderAsync(cancellationToken);
        var count = 0;
        while (await reader.ReadAsync(cancellationToken))
        {
            count++;
            this.logger.LogDebug("[{fileName}] {tableName} >> Retrieved [{elapsedMillis} ms]", this.command.Connection.FileName, this.tableName, sw.ElapsedMilliseconds);
            yield return reader;
        }

        this.logger.LogInformation("[{fileName}] {tableName} >> {result} [{elapsedMillis} ms]", this.command.Connection.FileName, this.tableName, count, sw.ElapsedMilliseconds);
    }

    public void Dispose()
    {
        this.command.Dispose();
    }
}
