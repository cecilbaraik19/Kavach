using Kavach.Core.Native;

namespace Kavach.Core.Infrastructure;

/// <summary>Checks used by "Low CPU / performance mode" to avoid disturbing the user.</summary>
public static class SystemState
{
    /// <summary>True when the laptop is running on battery.</summary>
    public static bool IsOnBattery()
    {
        try
        {
            if (!NativeMethods.GetSystemPowerStatus(out var status)) return false;
            // ACLineStatus: 0 = offline (battery), 1 = online, 255 = unknown. BatteryFlag 128 = no battery.
            return status.ACLineStatus == 0 && status.BatteryFlag != 128;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>True when a full-screen game, video or presentation is running (desktop session only).</summary>
    public static bool IsUserBusyFullscreen()
    {
        try
        {
            if (NativeMethods.SHQueryUserNotificationState(out var state) != 0) return false;
            // 2 = busy (full-screen app), 3 = Direct3D full screen (game), 4 = presentation mode
            return state is 2 or 3 or 4;
        }
        catch
        {
            return false;
        }
    }

    public static int WorkerCount(PerformanceMode mode)
    {
        var cores = Environment.ProcessorCount;
        return mode switch
        {
            PerformanceMode.Low => 1,
            PerformanceMode.Fast => Math.Max(2, cores),
            _ => Math.Max(2, cores / 2)
        };
    }
}
