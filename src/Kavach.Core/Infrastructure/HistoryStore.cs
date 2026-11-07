namespace Kavach.Core.Infrastructure;

/// <summary>Keeps the list of past scans (newest first) in history.json.</summary>
public sealed class HistoryStore
{
    private const int MaxScans = 200;
    private const int MaxDetectionsPerScan = 500;
    private readonly object _lock = new();

    public event Action? Changed;

    public List<ScanSummary> All()
    {
        lock (_lock)
        {
            return JsonStore.Load(AppPaths.HistoryFile, () => new List<ScanSummary>());
        }
    }

    public void Add(ScanSummary summary)
    {
        lock (_lock)
        {
            var list = JsonStore.Load(AppPaths.HistoryFile, () => new List<ScanSummary>());
            list.RemoveAll(s => s.Id == summary.Id);

            var copy = new ScanSummary
            {
                Id = summary.Id,
                Type = summary.Type,
                Status = summary.Status,
                Started = summary.Started,
                Finished = summary.Finished,
                FilesScanned = summary.FilesScanned,
                FilesSkipped = summary.FilesSkipped,
                ThreatsFound = summary.ThreatsFound,
                Targets = summary.Targets.Take(20).ToList(),
                Detections = summary.Detections.Take(MaxDetectionsPerScan).ToList(),
                Error = summary.Error
            };

            list.Insert(0, copy);
            if (list.Count > MaxScans) list.RemoveRange(MaxScans, list.Count - MaxScans);
            JsonStore.Save(AppPaths.HistoryFile, list);
        }
        Changed?.Invoke();
    }

    /// <summary>Update the "action taken" text of a detection after the user quarantines/kills it.</summary>
    public void UpdateDetectionAction(string detectionId, string action)
    {
        lock (_lock)
        {
            var list = JsonStore.Load(AppPaths.HistoryFile, () => new List<ScanSummary>());
            var changed = false;
            foreach (var d in list.SelectMany(s => s.Detections).Where(d => d.Id == detectionId))
            {
                d.ActionTaken = action;
                changed = true;
            }
            if (changed) JsonStore.Save(AppPaths.HistoryFile, list);
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            JsonStore.Save(AppPaths.HistoryFile, new List<ScanSummary>());
        }
        Changed?.Invoke();
    }
}
