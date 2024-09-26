namespace Badge.Models;

public sealed class StatusResponse
{
    public string? Version { get; set; } = Program.Version;
    public string? ApplicationName { get; set; } = Program.ApplicationName;
    public string? Environment { get; set; } = "Development";
    public DateTime? StartedAt { get; set; } = Program.StartTime;
}
