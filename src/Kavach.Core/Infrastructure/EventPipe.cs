using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace Kavach.Core.Infrastructure;

/// <summary>
/// The Kavach service (running as SYSTEM, without a screen) sends alerts to the Kavach app through
/// a named pipe. The app shows them as Windows notifications.
/// </summary>
public sealed class EventPipeServer : IDisposable
{
    private readonly List<StreamWriter> _clients = new();
    private readonly object _lock = new();
    private readonly CancellationTokenSource _cts = new();

    public void Start()
    {
        Task.Run(() => AcceptLoop(_cts.Token));
    }

    private async Task AcceptLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                var security = new PipeSecurity();
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                    PipeAccessRights.ReadWrite, AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.FullControl, AccessControlType.Allow));

                pipe = NamedPipeServerStreamAcl.Create(AppPaths.EventPipeName, PipeDirection.Out,
                    NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    0, 0, security);

                await pipe.WaitForConnectionAsync(token);
                var writer = new StreamWriter(pipe) { AutoFlush = true };
                lock (_lock) _clients.Add(writer);
                pipe = null; // now owned by the writer
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(1000, CancellationToken.None);
            }
            finally
            {
                pipe?.Dispose();
            }
        }
    }

    public void Broadcast(HostEvent e)
    {
        var line = JsonSerializer.Serialize(e, JsonStore.Options).Replace("\r", "").Replace("\n", "");
        lock (_lock)
        {
            for (var i = _clients.Count - 1; i >= 0; i--)
            {
                try
                {
                    _clients[i].WriteLine(line);
                }
                catch
                {
                    try { _clients[i].Dispose(); } catch { }
                    _clients.RemoveAt(i); // app was closed
                }
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        lock (_lock)
        {
            foreach (var c in _clients)
            {
                try { c.Dispose(); } catch { }
            }
            _clients.Clear();
        }
    }
}

/// <summary>Used by the app to receive alerts from the service.</summary>
public sealed class EventPipeClient : IDisposable
{
    private readonly CancellationTokenSource _cts = new();

    public event Action<HostEvent>? EventReceived;
    public event Action<bool>? ConnectionChanged;
    public bool IsConnected { get; private set; }

    /// <summary>Quick check: is the Kavach service running and accepting connections?</summary>
    public static bool IsServiceRunning()
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", AppPaths.EventPipeName, PipeDirection.In);
            pipe.Connect(700);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void Start() => Task.Run(() => Loop(_cts.Token));

    private async Task Loop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", AppPaths.EventPipeName, PipeDirection.In, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(5000, token);
                SetConnected(true);
                using var reader = new StreamReader(pipe);
                while (!token.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(token);
                    if (line == null) break;
                    try
                    {
                        var e = JsonSerializer.Deserialize<HostEvent>(line, JsonStore.Options);
                        if (e != null) EventReceived?.Invoke(e);
                    }
                    catch (JsonException)
                    {
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // service not running yet
            }
            SetConnected(false);
            try { await Task.Delay(5000, token); } catch (OperationCanceledException) { break; }
        }
    }

    private void SetConnected(bool value)
    {
        if (IsConnected == value) return;
        IsConnected = value;
        ConnectionChanged?.Invoke(value);
    }

    public void Dispose() => _cts.Cancel();
}
