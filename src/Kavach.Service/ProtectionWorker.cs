using Kavach.Core;
using Kavach.Core.Infrastructure;
using Kavach.Core.Protection;

namespace Kavach.Service;

/// <summary>Starts Kavach protection when Windows starts and stops it when the service stops.</summary>
public sealed class ProtectionWorker : BackgroundService
{
    private readonly ILogger<ProtectionWorker> _logger;
    private KavachContext? _ctx;
    private ProtectionHost? _host;
    private EventPipeServer? _pipe;

    public ProtectionWorker(ILogger<ProtectionWorker> logger)
    {
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            _ctx = KavachContext.Create();
            _pipe = new EventPipeServer();
            _pipe.Start();

            _host = new ProtectionHost(_ctx, isService: true);
            _host.EventRaised += e =>
            {
                _pipe.Broadcast(e);
                _logger.LogInformation("{Title}: {Message}", e.Title, e.Message);
            };
            _host.Start();

            _ctx.Log.Info("Service", $"Kavach service started (signatures: {_ctx.Hashes.Count:N0} hashes, {_ctx.Rules.Rules.Count} rules)");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Kavach protection failed to start");
            throw;
        }

        // Keep running until Windows asks the service to stop
        return Task.Delay(Timeout.Infinite, stoppingToken).ContinueWith(_ => { }, TaskScheduler.Default);
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _ctx?.Log.Warning("Service", "Kavach service is stopping");
        _host?.Dispose();
        _pipe?.Dispose();
        _ctx?.Cache.Save();
        return base.StopAsync(cancellationToken);
    }
}
