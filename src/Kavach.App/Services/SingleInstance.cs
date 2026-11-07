using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Kavach.App.Services;

/// <summary>
/// Makes sure only one Kavach window runs per user. When a second copy starts
/// (for example from the right-click "Scan with Kavach" menu) it passes its arguments to the first copy.
/// </summary>
public static class SingleInstance
{
    private static Mutex? _mutex;
    private static string PipeName => "Kavach.App." + new string(Environment.UserName.Where(char.IsLetterOrDigit).ToArray());

    public static bool TryAcquire()
    {
        _mutex = new Mutex(true, @"Local\Kavach.App.SingleInstance", out var createdNew);
        if (!createdNew)
        {
            _mutex.Dispose();
            _mutex = null;
        }
        return createdNew;
    }

    public static void SendToFirstInstance(string[] args)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
            client.Connect(2000);
            using var writer = new StreamWriter(client) { AutoFlush = true };
            writer.WriteLine(JsonSerializer.Serialize(args));
        }
        catch
        {
            // first instance is not listening; nothing else to do
        }
    }

    public static void Listen(Action<string[]> onArgs)
    {
        Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                    await server.WaitForConnectionAsync();
                    using var reader = new StreamReader(server);
                    var line = await reader.ReadLineAsync();
                    var args = line == null ? Array.Empty<string>() : JsonSerializer.Deserialize<string[]>(line) ?? Array.Empty<string>();
                    onArgs(args);
                }
                catch
                {
                    await Task.Delay(500);
                }
            }
        });
    }

    public static void Release()
    {
        try { _mutex?.ReleaseMutex(); } catch { }
        _mutex?.Dispose();
    }
}
