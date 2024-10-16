using Badge.Models.Identity;

namespace Badge.Models;

public sealed class OAuthCode(
    string code,
    UserIdentifier userId,
    ApplicationIdentifier clientId,
    DateTime notBefore,
    DateTime notAfter,
    string username,
    string scope,
    string redirect,
    string? codeChallenge,
    CodeChallengeMethods codeChallengeMethod,
    string state)
{
    public string Code { get; } = code;
    public UserIdentifier UserId { get; } = userId;
    public ApplicationIdentifier ClientId { get; } = clientId;
    public DateTime NotBefore { get; } = notBefore;
    public DateTime NotAfter { get; } = notAfter;
    public string Username { get; } = username;
    public string Scope { get; } = scope;
    public string Redirect { get; } = redirect;
    public string? CodeChallenge { get; } = codeChallenge;
    public CodeChallengeMethods CodeChallengeMethod { get; } = codeChallengeMethod;
    public string State { get; } = state;
}
