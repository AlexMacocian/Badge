﻿using Badge.Models.Identity;

namespace Badge.Models;

public sealed class ApplicationDetails(ApplicationIdentifier id, string name, string logoBase64)
{
    public ApplicationIdentifier Id { get; } = id;
    public string Name { get; } = name;
    public string LogoBase64 { get; } = logoBase64;
}
