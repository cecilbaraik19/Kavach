using Kavach.Service;

// Kavach background service.
// Installed by the setup program as the Windows service "KavachService" (runs as LocalSystem, starts automatically).
// It keeps real-time, ransomware and USB protection and scheduled scans running even when the Kavach window is closed.

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "KavachService");
builder.Services.AddHostedService<ProtectionWorker>();

var host = builder.Build();
host.Run();
