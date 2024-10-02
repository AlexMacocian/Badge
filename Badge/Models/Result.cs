namespace Badge.Models;

public abstract class Result
{
    public static Result<T> Success<T>(T result) => new Result<T>.Success(result);
    public static Result<T> Failure<T>(int errorCode, string errorMessage) => new Result<T>.Failure(errorCode, errorMessage);
}

public abstract class Result<T> : Result
{
    public sealed class Success(T result) : Result<T>
    {
        public T Result { get; } = result;
    }

    public sealed class Failure(int errorCode, string errorMessage) : Result<T>
    {
        public int ErrorCode { get; } = errorCode;
        public string ErrorMessage { get; } = errorMessage;
    }
}
