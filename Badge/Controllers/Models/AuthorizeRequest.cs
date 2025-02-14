﻿using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public class AuthorizeRequest
{
    [JsonPropertyName("clientId")]
    public string? ClientId { get; set; }
    [JsonPropertyName("clientSecret")]
    public string? ClientSecret { get; set; }
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
    [JsonPropertyName("state")]
    public string? State { get; set; }
    [JsonPropertyName("redirectUri")]
    public string? RedirectUri { get; set; }
    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }
    [JsonPropertyName("responseType")]
    public string? ResponseType { get; set; }
    [JsonPropertyName("codeChallenge")]
    public string? CodeChallenge { get; set; }
    [JsonPropertyName("codeChallengeMethod")]
    public string? CodeChallengeMethod { get; set; }
}
