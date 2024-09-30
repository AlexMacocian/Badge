using Badge.Controllers.Models;
using Badge.Models;
using Badge.Models.JsonWebKeys;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

namespace Badge;

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
[JsonSerializable(typeof(AuthorizeResponse))]
[JsonSerializable(typeof(Application))]
[JsonSerializable(typeof(List<Application>))]
[JsonSerializable(typeof(CreateApplicationRequest))]
[JsonSerializable(typeof(ApplicationWithRights))]
[JsonSerializable(typeof(List<ApplicationWithRights>))]
public partial class SerializationContext : JsonSerializerContext
{
}
