using Badge.Controllers.Models;
using Badge.Models;
using Badge.Models.JsonWebKeys;
using Badge.Services.OAuth2.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

namespace Badge;

[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(StatusResponse))]
[JsonSerializable(typeof(ProblemDetails))]
[JsonSerializable(typeof(JsonWebKeySetResponse))]
[JsonSerializable(typeof(JsonWebKey))]
[JsonSerializable(typeof(RSAJsonWebKey))]
[JsonSerializable(typeof(DSAJsonWebKey))]
[JsonSerializable(typeof(ECDsaJsonWebKey))]
[JsonSerializable(typeof(UsernameWithPassword))]
[JsonSerializable(typeof(UserDetails))]
[JsonSerializable(typeof(AuthorizeRequest))]
[JsonSerializable(typeof(CreateApplicationRequest))]
[JsonSerializable(typeof(ApplicationResponse))]
[JsonSerializable(typeof(ApplicationDetailsResponse))]
[JsonSerializable(typeof(List<ApplicationResponse>))]
[JsonSerializable(typeof(ClientSecretResponse))]
[JsonSerializable(typeof(List<ClientSecretResponse>))]
[JsonSerializable(typeof(ClientSecretResponseWithPassword))]
[JsonSerializable(typeof(UpdateClientSecretDetailRequest))]
[JsonSerializable(typeof(UpdateApplicationScopesRequest))]
[JsonSerializable(typeof(OAuthDiscoveryDocument))]
[JsonSerializable(typeof(OAuthScope))]
[JsonSerializable(typeof(IEnumerable<OAuthScopeResponse>))]
[JsonSerializable(typeof(OAuthResponse))]
[JsonSerializable(typeof(UserInfoResponse))]
public partial class SerializationContext : JsonSerializerContext
{
}
