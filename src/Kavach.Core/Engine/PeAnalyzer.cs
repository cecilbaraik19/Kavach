using System.Text;

namespace Kavach.Core.Engine;

/// <summary>Information read from a Windows program (.exe / .dll) file.</summary>
public sealed class PeInfo
{
    public bool IsPe { get; set; }
    public bool Is64Bit { get; set; }
    public bool IsDll { get; set; }
    public bool HasEmbeddedSignature { get; set; }
    public uint EntryPointRva { get; set; }
    public List<PeSection> Sections { get; } = new();
    public HashSet<string> ImportedFunctions { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ImportedDlls { get; } = new(StringComparer.OrdinalIgnoreCase);
    public double FileEntropy { get; set; }
}

public sealed class PeSection
{
    public string Name { get; set; } = "";
    public uint VirtualAddress { get; set; }
    public uint VirtualSize { get; set; }
    public uint RawSize { get; set; }
    public uint RawPointer { get; set; }
    public uint Characteristics { get; set; }
    public double Entropy { get; set; }

    public bool IsExecutable => (Characteristics & 0x20000000) != 0;
    public bool IsWritable => (Characteristics & 0x80000000) != 0;
}

public sealed class HeuristicResult
{
    public int Score { get; set; }
    public List<string> Reasons { get; } = new();

    public void Add(int points, string reason)
    {
        Score += points;
        Reasons.Add(reason);
    }
}

/// <summary>
/// Reads the PE format used by Windows programs and scores how suspicious the file looks.
/// The score is based on packing, high entropy (encrypted code), odd section flags,
/// and dangerous Windows API functions (injection, keylogging, credential theft).
/// </summary>
public static class PeAnalyzer
{
    private static readonly Dictionary<string, string> PackerSections = new(StringComparer.OrdinalIgnoreCase)
    {
        ["UPX0"] = "UPX",
        ["UPX1"] = "UPX",
        [".aspack"] = "ASPack",
        [".adata"] = "ASPack",
        [".petite"] = "Petite",
        [".nsp0"] = "NsPack",
        [".nsp1"] = "NsPack",
        ["MPRESS1"] = "MPRESS",
        ["MPRESS2"] = "MPRESS",
        [".themida"] = "Themida",
        [".vmp0"] = "VMProtect",
        [".vmp1"] = "VMProtect",
        [".enigma1"] = "Enigma",
        [".MPRESS1"] = "MPRESS",
        ["pebundle"] = "PEBundle",
        [".perplex"] = "Perplex",
        [".yP"] = "Y0da"
    };

    private static readonly string[] InjectionApis =
    {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
        "NtWriteVirtualMemory", "RtlCreateUserThread"
    };

    private static readonly string[] KeyloggerApis =
    {
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState", "RegisterRawInputDevices"
    };

    private static readonly string[] CredentialApis =
    {
        "CredEnumerateA", "CredEnumerateW", "LsaRetrievePrivateData", "CryptUnprotectData",
        "SamIConnect", "LsaEnumerateLogonSessions"
    };

    private static readonly string[] AntiDebugApis =
    {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA"
    };

    private static readonly string[] ScreenCaptureApis = { "BitBlt", "GetDC", "CreateCompatibleBitmap" };

    public static bool LooksLikePe(byte[] data) => data.Length > 0x40 && data[0] == (byte)'M' && data[1] == (byte)'Z';

    public static PeInfo Parse(byte[] data)
    {
        var info = new PeInfo();
        try
        {
            if (!LooksLikePe(data)) return info;
            var peOffset = (int)BitConverter.ToUInt32(data, 0x3C);
            if (peOffset <= 0 || peOffset + 24 > data.Length) return info;
            if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0) return info;

            var fileHeader = peOffset + 4;
            var sectionCount = BitConverter.ToUInt16(data, fileHeader + 2);
            var optionalSize = BitConverter.ToUInt16(data, fileHeader + 16);
            var characteristics = BitConverter.ToUInt16(data, fileHeader + 18);
            var optional = fileHeader + 20;
            if (optional + optionalSize > data.Length || optionalSize < 96) return info;

            var magic = BitConverter.ToUInt16(data, optional);
            info.IsPe = true;
            info.Is64Bit = magic == 0x20B;
            info.IsDll = (characteristics & 0x2000) != 0;
            info.EntryPointRva = BitConverter.ToUInt32(data, optional + 16);

            var dataDirs = optional + (info.Is64Bit ? 112 : 96);

            // Sections
            var sectionTable = optional + optionalSize;
            for (var i = 0; i < sectionCount && i < 96; i++)
            {
                var s = sectionTable + i * 40;
                if (s + 40 > data.Length) break;
                var section = new PeSection
                {
                    Name = Encoding.ASCII.GetString(data, s, 8).TrimEnd('\0'),
                    VirtualSize = BitConverter.ToUInt32(data, s + 8),
                    VirtualAddress = BitConverter.ToUInt32(data, s + 12),
                    RawSize = BitConverter.ToUInt32(data, s + 16),
                    RawPointer = BitConverter.ToUInt32(data, s + 20),
                    Characteristics = BitConverter.ToUInt32(data, s + 36)
                };
                if (section.RawPointer < data.Length && section.RawSize > 0)
                {
                    var length = (int)Math.Min(section.RawSize, (uint)(data.Length - section.RawPointer));
                    section.Entropy = Entropy(data, (int)section.RawPointer, length);
                }
                info.Sections.Add(section);
            }

            // Embedded digital signature = security directory (index 4)
            if (dataDirs + 5 * 8 <= data.Length)
            {
                var certSize = BitConverter.ToUInt32(data, dataDirs + 4 * 8 + 4);
                info.HasEmbeddedSignature = certSize > 0;
            }

            // Imports (index 1)
            if (dataDirs + 2 * 8 <= data.Length)
            {
                var importRva = BitConverter.ToUInt32(data, dataDirs + 8);
                if (importRva != 0) ReadImports(data, info, importRva);
            }

            info.FileEntropy = Entropy(data, 0, data.Length);
        }
        catch (ArgumentException)
        {
            // damaged file: keep what we have
        }
        catch (IndexOutOfRangeException)
        {
        }
        return info;
    }

    private static int RvaToOffset(PeInfo info, uint rva)
    {
        foreach (var s in info.Sections)
        {
            var size = Math.Max(s.VirtualSize, s.RawSize);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
            {
                return (int)(rva - s.VirtualAddress + s.RawPointer);
            }
        }
        return -1;
    }

    private static string ReadAsciiZ(byte[] data, int offset, int max = 256)
    {
        if (offset < 0 || offset >= data.Length) return "";
        var end = offset;
        while (end < data.Length && end - offset < max && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data, offset, end - offset);
    }

    private static void ReadImports(byte[] data, PeInfo info, uint importRva)
    {
        var descriptor = RvaToOffset(info, importRva);
        if (descriptor < 0) return;

        for (var d = 0; d < 256; d++, descriptor += 20)
        {
            if (descriptor + 20 > data.Length) break;
            var originalThunk = BitConverter.ToUInt32(data, descriptor);
            var nameRva = BitConverter.ToUInt32(data, descriptor + 12);
            var firstThunk = BitConverter.ToUInt32(data, descriptor + 16);
            if (nameRva == 0 && firstThunk == 0) break;

            var dllName = ReadAsciiZ(data, RvaToOffset(info, nameRva));
            if (dllName.Length > 0) info.ImportedDlls.Add(dllName);

            var thunkOffset = RvaToOffset(info, originalThunk != 0 ? originalThunk : firstThunk);
            if (thunkOffset < 0) continue;

            var step = info.Is64Bit ? 8 : 4;
            for (var t = 0; t < 4096; t++, thunkOffset += step)
            {
                if (thunkOffset + step > data.Length) break;
                ulong value = info.Is64Bit ? BitConverter.ToUInt64(data, thunkOffset) : BitConverter.ToUInt32(data, thunkOffset);
                if (value == 0) break;
                var byOrdinal = info.Is64Bit ? (value & 0x8000000000000000UL) != 0 : (value & 0x80000000UL) != 0;
                if (byOrdinal) continue;

                var hintName = RvaToOffset(info, (uint)(value & 0x7FFFFFFF));
                if (hintName < 0) continue;
                var function = ReadAsciiZ(data, hintName + 2);
                if (function.Length > 0) info.ImportedFunctions.Add(function);
            }
        }
    }

    /// <summary>Shannon entropy from 0 (all the same byte) to 8 (random / encrypted).</summary>
    public static double Entropy(byte[] data, int offset, int length)
    {
        if (length <= 0) return 0;
        Span<int> counts = stackalloc int[256];
        var end = Math.Min(data.Length, offset + length);
        for (var i = offset; i < end; i++) counts[data[i]]++;

        double entropy = 0;
        var total = (double)(end - offset);
        foreach (var c in counts)
        {
            if (c == 0) continue;
            var p = c / total;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>Gives a suspicion score. 45+ = Medium, 70+ = High.</summary>
    public static HeuristicResult Score(PeInfo pe)
    {
        var result = new HeuristicResult();
        if (!pe.IsPe) return result;

        // 1. Known packer sections
        var packers = pe.Sections
            .Select(s => PackerSections.TryGetValue(s.Name, out var p) ? p : null)
            .Where(p => p != null)
            .Distinct()
            .ToList();
        if (packers.Count > 0) result.Add(25, $"Packed with {string.Join(", ", packers)}");

        // 2. Encrypted / compressed executable code
        var highEntropyCode = pe.Sections.Where(s => s.IsExecutable && s.Entropy > 7.2).ToList();
        if (highEntropyCode.Count > 0)
            result.Add(20, $"Encrypted or packed code section ({highEntropyCode[0].Name}, entropy {highEntropyCode[0].Entropy:0.0})");
        else if (pe.FileEntropy > 7.4)
            result.Add(10, $"Very high file entropy ({pe.FileEntropy:0.0})");

        // 3. Sections that are both writable and executable
        var rwx = pe.Sections.Where(s => s.IsExecutable && s.IsWritable).ToList();
        if (rwx.Count > 0) result.Add(15, $"Writable + executable section ({rwx[0].Name})");

        // 4. Entry point in an unusual place
        if (pe.EntryPointRva != 0 && pe.Sections.Count > 0)
        {
            var epSection = pe.Sections.FirstOrDefault(s =>
                pe.EntryPointRva >= s.VirtualAddress && pe.EntryPointRva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize));
            if (epSection == null)
                result.Add(20, "Entry point is outside all sections");
            else if (epSection.IsWritable)
                result.Add(10, $"Entry point is in a writable section ({epSection.Name})");
        }

        // 5. Hidden imports (loads functions by name at run time)
        var imports = pe.ImportedFunctions;
        if (!pe.IsDll && imports.Count > 0 && imports.Count < 6 &&
            imports.Contains("GetProcAddress") && (imports.Contains("LoadLibraryA") || imports.Contains("LoadLibraryW")))
        {
            result.Add(15, "Very few imports (hides what it does)");
        }
        else if (!pe.IsDll && imports.Count == 0 && pe.Sections.Count > 0)
        {
            result.Add(10, "No import table");
        }

        // 6. Dangerous API groups
        var injection = InjectionApis.Where(imports.Contains).ToList();
        if (injection.Count >= 2) result.Add(25, $"Process injection functions ({string.Join(", ", injection.Take(3))})");

        var keylog = KeyloggerApis.Where(imports.Contains).ToList();
        if (keylog.Count >= 2) result.Add(15, $"Keyboard capture functions ({string.Join(", ", keylog.Take(3))})");

        var creds = CredentialApis.Where(imports.Contains).ToList();
        if (creds.Count >= 1) result.Add(10, $"Credential access functions ({string.Join(", ", creds.Take(3))})");

        if (AntiDebugApis.Count(imports.Contains) >= 2) result.Add(5, "Anti-debugging checks");

        if (ScreenCaptureApis.All(imports.Contains) && keylog.Count >= 1)
            result.Add(10, "Screen capture together with keyboard capture");

        return result;
    }
}
