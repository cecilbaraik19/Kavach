using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Kavach.Core.Infrastructure;

namespace Kavach.Core.Engine;

/*
 * Kavach rule engine — a small YARA-compatible engine written in C#.
 *
 * Supported YARA features (enough for most simple community rules):
 *   rule Name : tags { meta: ... strings: ... condition: ... }
 *   Text strings    $a = "text"  with modifiers: nocase, wide, ascii, fullword
 *   Hex strings     $b = { 4D 5A ?? 9? [2] 00 }   (?? wildcards, nibble wildcards, fixed jumps [n])
 *   Regex strings   $c = /https?:\/\/[a-z]+/i
 *   Conditions      and, or, not, ( ), == != < <= > >=, +, -
 *                   $a, #a > 2, $a at 0, filesize < 2MB, true, false
 *                   any of them, all of them, 2 of ($a*), none of ($x, $y)
 *                   uint8(n), uint16(n), uint32(n), uint16be(n), uint32be(n)
 *   meta: severity = "low|medium|high|critical", threat = "Trojan.Name", description = "..."
 *
 * Not supported: modules (pe, math), for-loops, xor/base64 modifiers, hex alternatives (AA|BB), ranged jumps [2-4].
 * Rules using unsupported features are skipped and listed as errors on the Updates page.
 */

public sealed class RuleParseException : Exception
{
    public RuleParseException(string message) : base(message) { }
}

public enum RuleStringKind { Text, Hex, Regex }

public sealed class RuleString
{
    public string Id { get; init; } = "";
    public RuleStringKind Kind { get; init; }
    public bool NoCase { get; init; }
    public bool FullWord { get; init; }
    /// <summary>For text strings: the byte patterns to search for (ascii and/or wide).</summary>
    public List<byte[]> Patterns { get; init; } = new();
    /// <summary>For hex strings: bytes and their masks (0xFF = exact, 0x00 = any).</summary>
    public byte[] HexBytes { get; init; } = Array.Empty<byte>();
    public byte[] HexMask { get; init; } = Array.Empty<byte>();
    public Regex? Regex { get; init; }
}

public sealed class Rule
{
    public string Name { get; init; } = "";
    public string SourceFile { get; init; } = "";
    public List<string> Tags { get; init; } = new();
    public Dictionary<string, string> Meta { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public List<RuleString> Strings { get; init; } = new();
    internal Func<RuleContext, object> Condition { get; set; } = _ => false;

    public string ThreatName
    {
        get
        {
            if (Meta.TryGetValue("threat", out var t) && t.Length > 0) return t;
            // ReversingLabs style: tc_detection_type = "Ransomware", tc_detection_name = "WannaCry"
            if (Meta.TryGetValue("tc_detection_type", out var type) && Meta.TryGetValue("tc_detection_name", out var name) &&
                type.Length > 0 && name.Length > 0)
                return $"{type}.{name}".Replace(' ', '_');
            return "Rule." + Name;
        }
    }
    public string Description => Meta.TryGetValue("description", out var d) ? d : "";

    public ThreatLevel Level
    {
        get
        {
            if (!Meta.ContainsKey("severity") && Meta.TryGetValue("category", out var cat) &&
                !cat.Equals("MALWARE", StringComparison.OrdinalIgnoreCase))
                return ThreatLevel.Medium; // hacking tools, PUA … rather than real malware
            var s = Meta.TryGetValue("severity", out var v) ? v.ToLowerInvariant() : "high";
            return s switch
            {
                "low" => ThreatLevel.Low,
                "medium" => ThreatLevel.Medium,
                "critical" => ThreatLevel.Critical,
                _ => ThreatLevel.High
            };
        }
    }
}

public sealed record RuleMatch(Rule Rule, IReadOnlyList<string> MatchedStrings);

/// <summary>All rules loaded from Signatures\rules\*.yar and *.yara.</summary>
public sealed class RuleSet
{
    private List<Rule> _rules = new();

    public IReadOnlyList<Rule> Rules => _rules;
    public List<string> Errors { get; } = new();

    public void Load()
    {
        var rules = new List<Rule>();
        Errors.Clear();
        if (Directory.Exists(AppPaths.RulesDir))
        {
            foreach (var file in Directory.EnumerateFiles(AppPaths.RulesDir, "*.*", SearchOption.AllDirectories))
            {
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".yar" && ext != ".yara") continue;
                try
                {
                    var text = File.ReadAllText(file);
                    rules.AddRange(RuleParser.Parse(text, Path.GetFileName(file), Errors));
                }
                catch (Exception ex)
                {
                    Errors.Add($"{Path.GetFileName(file)}: {ex.Message}");
                }
            }
        }
        _rules = rules;
    }

    /// <summary>Checks rule text without loading it (used by "Import rules").</summary>
    public static int Validate(string text, string fileName, List<string> errors) =>
        RuleParser.Parse(text, fileName, errors).Count;

    public List<RuleMatch> Match(byte[] data, long fileSize)
    {
        var matches = new List<RuleMatch>();
        if (_rules.Count == 0 || data.Length == 0) return matches;

        var context = new RuleContext(data, fileSize);
        foreach (var rule in _rules)
        {
            try
            {
                context.BeginRule(rule);
                if (RuleContext.ToBool(rule.Condition(context)))
                {
                    matches.Add(new RuleMatch(rule, context.MatchedIds()));
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // a slow regex never blocks the scan
            }
            catch (IndexOutOfRangeException)
            {
                // uint32(offset) beyond the end of the file → rule simply does not match
            }
        }
        return matches;
    }
}

/// <summary>Data shared while evaluating rules against one file.</summary>
internal sealed class RuleContext
{
    private readonly byte[] _data;
    private byte[]? _lower;
    private string? _latin1;
    private string? _latin1Lower;
    private Rule _rule = new();
    private readonly Dictionary<int, int> _counts = new();

    public RuleContext(byte[] data, long fileSize)
    {
        _data = data;
        FileSize = fileSize;
    }

    public long FileSize { get; }
    public Rule CurrentRule => _rule;

    public void BeginRule(Rule rule)
    {
        _rule = rule;
        _counts.Clear();
    }

    public List<string> MatchedIds()
    {
        var ids = new List<string>();
        foreach (var kv in _counts)
        {
            if (kv.Value > 0) ids.Add(_rule.Strings[kv.Key].Id);
        }
        return ids;
    }

    private byte[] Lower
    {
        get
        {
            if (_lower != null) return _lower;
            var copy = new byte[_data.Length];
            for (var i = 0; i < copy.Length; i++)
            {
                var b = _data[i];
                copy[i] = b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;
            }
            return _lower = copy;
        }
    }

    private string Latin1 => _latin1 ??= Encoding.Latin1.GetString(_data);
    private string Latin1Lower => _latin1Lower ??= Encoding.Latin1.GetString(Lower);

    public long ReadInt(int size, long offset, bool bigEndian)
    {
        if (offset < 0 || offset + size > _data.Length) throw new IndexOutOfRangeException();
        long value = 0;
        for (var i = 0; i < size; i++)
        {
            var b = _data[offset + (bigEndian ? i : size - 1 - i)];
            value = (value << 8) | b;
        }
        return value;
    }

    public int Count(int index)
    {
        if (_counts.TryGetValue(index, out var cached)) return cached;
        var s = _rule.Strings[index];
        var count = s.Kind switch
        {
            RuleStringKind.Text => CountText(s),
            RuleStringKind.Hex => CountHex(s),
            _ => CountRegex(s)
        };
        _counts[index] = count;
        return count;
    }

    public bool MatchAt(int index, long offset)
    {
        var s = _rule.Strings[index];
        if (offset < 0 || offset >= _data.Length) return false;
        var o = (int)offset;
        switch (s.Kind)
        {
            case RuleStringKind.Text:
                var source = s.NoCase ? Lower : _data;
                foreach (var p in s.Patterns)
                {
                    if (o + p.Length <= source.Length && source.AsSpan(o, p.Length).SequenceEqual(p)) return true;
                }
                return false;
            case RuleStringKind.Hex:
                return HexEqual(s, o);
            default:
                var text = Latin1;
                var m = s.Regex!.Match(text, o);
                return m.Success && m.Index == o;
        }
    }

    private const int MaxCount = 1000;

    private int CountText(RuleString s)
    {
        var source = s.NoCase ? Lower : _data;
        var total = 0;
        foreach (var pattern in s.Patterns)
        {
            var span = source.AsSpan();
            var start = 0;
            while (start < span.Length && total < MaxCount)
            {
                var pos = span[start..].IndexOf(pattern);
                if (pos < 0) break;
                var abs = start + pos;
                if (!s.FullWord || IsFullWord(source, abs, pattern.Length)) total++;
                start = abs + 1;
            }
        }
        return total;
    }

    private static bool IsFullWord(byte[] data, int pos, int length)
    {
        static bool IsWordChar(byte b) => b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'_';
        var before = pos == 0 || !IsWordChar(data[pos - 1]);
        var end = pos + length;
        var after = end >= data.Length || !IsWordChar(data[end]);
        return before && after;
    }

    private int CountHex(RuleString s)
    {
        // Find the longest run of exact bytes and use it as a fast "anchor".
        int bestStart = -1, bestLen = 0;
        for (var i = 0; i < s.HexMask.Length;)
        {
            if (s.HexMask[i] != 0xFF) { i++; continue; }
            var j = i;
            while (j < s.HexMask.Length && s.HexMask[j] == 0xFF) j++;
            if (j - i > bestLen) { bestLen = j - i; bestStart = i; }
            i = j;
        }

        var total = 0;
        if (bestLen == 0)
        {
            for (var pos = 0; pos + s.HexBytes.Length <= _data.Length && total < MaxCount; pos++)
            {
                if (HexEqual(s, pos)) total++;
            }
            return total;
        }

        var anchor = s.HexBytes.AsSpan(bestStart, bestLen);
        var data = _data.AsSpan();
        var start = 0;
        while (start < data.Length && total < MaxCount)
        {
            var found = data[start..].IndexOf(anchor);
            if (found < 0) break;
            var anchorPos = start + found;
            var patternStart = anchorPos - bestStart;
            if (patternStart >= 0 && HexEqual(s, patternStart)) total++;
            start = anchorPos + 1;
        }
        return total;
    }

    private bool HexEqual(RuleString s, int pos)
    {
        if (pos < 0 || pos + s.HexBytes.Length > _data.Length) return false;
        for (var i = 0; i < s.HexBytes.Length; i++)
        {
            if ((_data[pos + i] & s.HexMask[i]) != (s.HexBytes[i] & s.HexMask[i])) return false;
        }
        return true;
    }

    private int CountRegex(RuleString s)
    {
        var text = Latin1;
        var count = 0;
        var m = s.Regex!.Match(text);
        while (m.Success && count < MaxCount)
        {
            count++;
            m = m.NextMatch();
        }
        return count;
    }

    public static bool ToBool(object v) => v switch
    {
        bool b => b,
        long l => l != 0,
        _ => false
    };

    public static long ToLong(object v) => v switch
    {
        long l => l,
        bool b => b ? 1 : 0,
        _ => 0
    };
}

/// <summary>Reads rule text and turns it into <see cref="Rule"/> objects.</summary>
internal sealed class RuleParser
{
    private readonly string _text;
    private int _pos;

    private RuleParser(string text) { _text = text; }

    public static List<Rule> Parse(string text, string fileName, List<string> errors)
    {
        var parser = new RuleParser(text);
        var rules = new List<Rule>();

        while (true)
        {
            parser.SkipWhitespace();
            if (parser.AtEnd) break;

            var ruleStart = parser._pos;
            try
            {
                var rule = parser.ParseNext(fileName);
                if (rule != null) rules.Add(rule);
            }
            catch (RuleParseException ex)
            {
                errors.Add($"{fileName}: {ex.Message}");
                // Skip to after the next closing brace at depth 0 so the next rule can still load.
                parser._pos = ruleStart;
                if (!parser.SkipToNextRule()) break;
            }
        }
        return rules;
    }

    private bool AtEnd => _pos >= _text.Length;
    private char Peek => _pos < _text.Length ? _text[_pos] : '\0';

    private bool SkipToNextRule()
    {
        var idx = _text.IndexOf('{', _pos);
        if (idx < 0) { _pos = _text.Length; return false; }
        var depth = 0;
        for (var i = idx; i < _text.Length; i++)
        {
            if (_text[i] == '"') { i = SkipQuoted(i); continue; }
            if (_text[i] == '{') depth++;
            else if (_text[i] == '}')
            {
                depth--;
                if (depth == 0) { _pos = i + 1; return true; }
            }
        }
        _pos = _text.Length;
        return false;
    }

    private int SkipQuoted(int i)
    {
        for (i++; i < _text.Length; i++)
        {
            if (_text[i] == '\\') { i++; continue; }
            if (_text[i] == '"') return i;
        }
        return i;
    }

    private void SkipWhitespace()
    {
        while (!AtEnd)
        {
            var c = Peek;
            if (char.IsWhiteSpace(c)) { _pos++; continue; }
            if (c == '/' && _pos + 1 < _text.Length && _text[_pos + 1] == '/')
            {
                while (!AtEnd && Peek != '\n') _pos++;
                continue;
            }
            if (c == '/' && _pos + 1 < _text.Length && _text[_pos + 1] == '*')
            {
                var end = _text.IndexOf("*/", _pos + 2, StringComparison.Ordinal);
                _pos = end < 0 ? _text.Length : end + 2;
                continue;
            }
            break;
        }
    }

    private string ReadIdent()
    {
        SkipWhitespace();
        var start = _pos;
        while (!AtEnd && (char.IsLetterOrDigit(Peek) || Peek == '_')) _pos++;
        if (start == _pos) throw new RuleParseException($"expected a name near position {_pos}");
        return _text[start.._pos];
    }

    private void Expect(char c)
    {
        SkipWhitespace();
        if (Peek != c) throw new RuleParseException($"expected '{c}' near position {_pos}");
        _pos++;
    }

    private string ReadQuoted()
    {
        SkipWhitespace();
        if (Peek != '"') throw new RuleParseException($"expected a quoted text near position {_pos}");
        _pos++;
        var sb = new StringBuilder();
        while (!AtEnd && Peek != '"')
        {
            var c = _text[_pos++];
            if (c == '\\' && !AtEnd)
            {
                var e = _text[_pos++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 't': sb.Append('\t'); break;
                    case 'r': sb.Append('\r'); break;
                    case '\\': sb.Append('\\'); break;
                    case '"': sb.Append('"'); break;
                    case 'x':
                        if (_pos + 2 > _text.Length) throw new RuleParseException("bad \\x escape");
                        sb.Append((char)Convert.ToByte(_text.Substring(_pos, 2), 16));
                        _pos += 2;
                        break;
                    default: sb.Append(e); break;
                }
            }
            else
            {
                sb.Append(c);
            }
        }
        if (AtEnd) throw new RuleParseException("text is not closed with \"");
        _pos++; // closing quote
        return sb.ToString();
    }

    private Rule? ParseNext(string fileName)
    {
        var word = ReadIdent();

        if (word is "import" or "include")
        {
            ReadQuoted(); // modules are not supported; rules that use them will fail later
            return null;
        }

        while (word is "private" or "global") word = ReadIdent();
        if (word != "rule") throw new RuleParseException($"expected 'rule' but found '{word}'");

        var name = ReadIdent();
        var tags = new List<string>();
        SkipWhitespace();
        if (Peek == ':')
        {
            _pos++;
            SkipWhitespace();
            while (!AtEnd && Peek != '{')
            {
                tags.Add(ReadIdent());
                SkipWhitespace();
            }
        }
        Expect('{');

        var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var strings = new List<RuleString>();
        string? conditionText = null;

        while (true)
        {
            SkipWhitespace();
            if (Peek == '}') { _pos++; break; }
            var section = ReadIdent();
            Expect(':');
            switch (section)
            {
                case "meta":
                    ParseMeta(meta);
                    break;
                case "strings":
                    ParseStrings(strings, name);
                    break;
                case "condition":
                    conditionText = ReadConditionText();
                    break;
                default:
                    throw new RuleParseException($"unknown section '{section}' in rule {name}");
            }
            if (conditionText != null)
            {
                Expect('}');
                break;
            }
        }

        if (conditionText == null) throw new RuleParseException($"rule {name} has no condition");

        var rule = new Rule { Name = name, Tags = tags, Meta = meta, Strings = strings, SourceFile = fileName };
        rule.Condition = new ConditionParser(conditionText, rule).Parse();
        return rule;
    }

    private bool NextIsSection()
    {
        var save = _pos;
        try
        {
            SkipWhitespace();
            if (!char.IsLetter(Peek)) return false;
            var word = ReadIdent();
            SkipWhitespace();
            return word is "meta" or "strings" or "condition" && Peek == ':';
        }
        catch (RuleParseException)
        {
            return false;
        }
        finally
        {
            _pos = save;
        }
    }

    private void ParseMeta(Dictionary<string, string> meta)
    {
        while (true)
        {
            SkipWhitespace();
            if (Peek == '}' || NextIsSection()) return;
            var key = ReadIdent();
            Expect('=');
            SkipWhitespace();
            string value;
            if (Peek == '"') value = ReadQuoted();
            else
            {
                var start = _pos;
                while (!AtEnd && !char.IsWhiteSpace(Peek) && Peek != '}') _pos++;
                value = _text[start.._pos];
            }
            meta[key] = value;
        }
    }

    private void ParseStrings(List<RuleString> strings, string ruleName)
    {
        while (true)
        {
            SkipWhitespace();
            if (Peek == '}' || NextIsSection()) return;
            if (Peek != '$') throw new RuleParseException($"expected $name in strings of rule {ruleName}");
            var start = _pos;
            _pos++;
            while (!AtEnd && (char.IsLetterOrDigit(Peek) || Peek == '_')) _pos++;
            var id = _text[start.._pos];
            if (id == "$") id = "$anon" + strings.Count;

            Expect('=');
            SkipWhitespace();

            if (Peek == '"')
            {
                var text = ReadQuoted();
                var mods = ReadModifiers();
                strings.Add(BuildText(id, text, mods));
            }
            else if (Peek == '{')
            {
                strings.Add(ParseHex(id));
                ReadModifiers();
            }
            else if (Peek == '/')
            {
                strings.Add(ParseRegex(id));
            }
            else
            {
                throw new RuleParseException($"bad value for {id} in rule {ruleName}");
            }
        }
    }

    private HashSet<string> ReadModifiers()
    {
        var mods = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            SkipWhitespace();
            if (!char.IsLetter(Peek) || NextIsSection()) break;
            var word = ReadIdent();
            if (word is "xor" or "base64" or "base64wide")
                throw new RuleParseException($"modifier '{word}' is not supported");
            mods.Add(word);
        }
        return mods;
    }

    private static RuleString BuildText(string id, string text, HashSet<string> mods)
    {
        var noCase = mods.Contains("nocase");
        var wide = mods.Contains("wide");
        var ascii = mods.Contains("ascii") || !wide;
        if (noCase) text = text.ToLowerInvariant();

        var patterns = new List<byte[]>();
        if (ascii) patterns.Add(Encoding.Latin1.GetBytes(text));
        if (wide) patterns.Add(Encoding.Unicode.GetBytes(text));

        return new RuleString
        {
            Id = id,
            Kind = RuleStringKind.Text,
            NoCase = noCase,
            FullWord = mods.Contains("fullword"),
            Patterns = patterns
        };
    }

    private RuleString ParseHex(string id)
    {
        Expect('{');
        var end = _text.IndexOf('}', _pos);
        if (end < 0) throw new RuleParseException($"hex string {id} is not closed");
        var body = _text[_pos..end];
        _pos = end + 1;

        var bytes = new List<byte>();
        var mask = new List<byte>();
        var i = 0;
        while (i < body.Length)
        {
            var c = body[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '[')
            {
                var close = body.IndexOf(']', i);
                if (close < 0) throw new RuleParseException($"bad jump in {id}");
                var inside = body[(i + 1)..close].Trim();
                if (inside.Contains('-')) throw new RuleParseException($"ranged jumps like [{inside}] are not supported ({id})");
                var n = int.Parse(inside, CultureInfo.InvariantCulture);
                for (var k = 0; k < n; k++) { bytes.Add(0); mask.Add(0); }
                i = close + 1;
                continue;
            }
            if (c is '(' or '|' or ')') throw new RuleParseException($"hex alternatives are not supported ({id})");
            if (i + 1 >= body.Length) throw new RuleParseException($"odd number of hex digits in {id}");

            var hi = body[i];
            var lo = body[i + 1];
            byte value = 0, m = 0;
            if (hi != '?') { value |= (byte)(Convert.ToByte(hi.ToString(), 16) << 4); m |= 0xF0; }
            if (lo != '?') { value |= Convert.ToByte(lo.ToString(), 16); m |= 0x0F; }
            bytes.Add(value);
            mask.Add(m);
            i += 2;
        }

        if (bytes.Count == 0) throw new RuleParseException($"empty hex string {id}");
        return new RuleString { Id = id, Kind = RuleStringKind.Hex, HexBytes = bytes.ToArray(), HexMask = mask.ToArray() };
    }

    private RuleString ParseRegex(string id)
    {
        _pos++; // opening '/'
        var sb = new StringBuilder();
        while (!AtEnd && Peek != '/')
        {
            if (Peek == '\\' && _pos + 1 < _text.Length && _text[_pos + 1] == '/')
            {
                sb.Append('/');
                _pos += 2;
                continue;
            }
            sb.Append(_text[_pos++]);
        }
        if (AtEnd) throw new RuleParseException($"regex {id} is not closed");
        _pos++;

        var options = RegexOptions.CultureInvariant;
        while (!AtEnd && (Peek == 'i' || Peek == 's'))
        {
            options |= Peek == 'i' ? RegexOptions.IgnoreCase : RegexOptions.Singleline;
            _pos++;
        }
        var mods = ReadModifiers();
        if (mods.Contains("nocase")) options |= RegexOptions.IgnoreCase;

        try
        {
            var regex = new Regex(sb.ToString(), options, TimeSpan.FromSeconds(1));
            return new RuleString { Id = id, Kind = RuleStringKind.Regex, Regex = regex, NoCase = (options & RegexOptions.IgnoreCase) != 0 };
        }
        catch (ArgumentException ex)
        {
            throw new RuleParseException($"bad regex {id}: {ex.Message}");
        }
    }

    /// <summary>The condition is everything until the closing '}' of the rule.</summary>
    private string ReadConditionText()
    {
        var start = _pos;
        var depth = 0;
        while (!AtEnd)
        {
            var c = Peek;
            if (c == '"') { _pos = SkipQuoted(_pos) + 1; continue; }
            if (c == '/' && _pos + 1 < _text.Length && (_text[_pos + 1] == '/' || _text[_pos + 1] == '*'))
            {
                SkipWhitespace();
                continue;
            }
            if (c == '{') depth++;
            if (c == '}')
            {
                if (depth == 0) break;
                depth--;
            }
            _pos++;
        }
        return _text[start.._pos];
    }
}

/// <summary>Turns a condition like "uint16(0) == 0x5A4D and 2 of ($a*)" into code.</summary>
internal sealed class ConditionParser
{
    private readonly List<string> _tokens;
    private readonly Rule _rule;
    private int _i;

    public ConditionParser(string text, Rule rule)
    {
        _rule = rule;
        _tokens = Tokenize(text);
    }

    public Func<RuleContext, object> Parse()
    {
        if (_tokens.Count == 0) throw new RuleParseException($"empty condition in rule {_rule.Name}");
        var expr = ParseOr();
        if (_i < _tokens.Count) throw new RuleParseException($"unexpected '{_tokens[_i]}' in condition of {_rule.Name}");
        return expr;
    }

    private string? Peek => _i < _tokens.Count ? _tokens[_i] : null;
    private string Next() => _i < _tokens.Count ? _tokens[_i++] : throw new RuleParseException($"condition of {_rule.Name} ends too early");

    private void Expect(string t)
    {
        var n = Next();
        if (n != t) throw new RuleParseException($"expected '{t}' but found '{n}' in {_rule.Name}");
    }

    private static List<string> Tokenize(string text)
    {
        var tokens = new List<string>();
        var i = 0;
        while (i < text.Length)
        {
            var c = text[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '/' && i + 1 < text.Length && text[i + 1] == '/')
            {
                while (i < text.Length && text[i] != '\n') i++;
                continue;
            }
            if (c == '/' && i + 1 < text.Length && text[i + 1] == '*')
            {
                var end = text.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? text.Length : end + 2;
                continue;
            }
            if (i + 1 < text.Length)
            {
                var two = text.Substring(i, 2);
                if (two is "==" or "!=" or "<=" or ">=")
                {
                    tokens.Add(two);
                    i += 2;
                    continue;
                }
            }
            if (c is '$' or '#' or '@' or '!')
            {
                var start = i++;
                while (i < text.Length && (char.IsLetterOrDigit(text[i]) || text[i] == '_' || text[i] == '*')) i++;
                tokens.Add(text[start..i]);
                continue;
            }
            if (char.IsLetterOrDigit(c) || c == '_')
            {
                var start = i;
                while (i < text.Length && (char.IsLetterOrDigit(text[i]) || text[i] == '_')) i++;
                tokens.Add(text[start..i]);
                continue;
            }
            tokens.Add(c.ToString());
            i++;
        }
        return tokens;
    }

    private Func<RuleContext, object> ParseOr()
    {
        var left = ParseAnd();
        while (Peek == "or")
        {
            _i++;
            var l = left;
            var r = ParseAnd();
            left = ctx => RuleContext.ToBool(l(ctx)) || RuleContext.ToBool(r(ctx));
        }
        return left;
    }

    private Func<RuleContext, object> ParseAnd()
    {
        var left = ParseNot();
        while (Peek == "and")
        {
            _i++;
            var l = left;
            var r = ParseNot();
            left = ctx => RuleContext.ToBool(l(ctx)) && RuleContext.ToBool(r(ctx));
        }
        return left;
    }

    private Func<RuleContext, object> ParseNot()
    {
        if (Peek == "not")
        {
            _i++;
            var inner = ParseNot();
            return ctx => !RuleContext.ToBool(inner(ctx));
        }
        return ParseComparison();
    }

    private Func<RuleContext, object> ParseComparison()
    {
        var left = ParseAdd();
        var op = Peek;
        if (op is "==" or "!=" or "<" or "<=" or ">" or ">=")
        {
            _i++;
            var right = ParseAdd();
            return op switch
            {
                "==" => ctx => RuleContext.ToLong(left(ctx)) == RuleContext.ToLong(right(ctx)),
                "!=" => ctx => RuleContext.ToLong(left(ctx)) != RuleContext.ToLong(right(ctx)),
                "<" => ctx => RuleContext.ToLong(left(ctx)) < RuleContext.ToLong(right(ctx)),
                "<=" => ctx => RuleContext.ToLong(left(ctx)) <= RuleContext.ToLong(right(ctx)),
                ">" => ctx => RuleContext.ToLong(left(ctx)) > RuleContext.ToLong(right(ctx)),
                _ => ctx => RuleContext.ToLong(left(ctx)) >= RuleContext.ToLong(right(ctx))
            };
        }
        return left;
    }

    private Func<RuleContext, object> ParseAdd()
    {
        var left = ParsePrimary();
        while (Peek is "+" or "-")
        {
            var op = Next();
            var l = left;
            var r = ParsePrimary();
            left = op == "+"
                ? ctx => RuleContext.ToLong(l(ctx)) + RuleContext.ToLong(r(ctx))
                : ctx => RuleContext.ToLong(l(ctx)) - RuleContext.ToLong(r(ctx));
        }
        return left;
    }

    private Func<RuleContext, object> ParsePrimary()
    {
        var t = Next();

        if (t == "(")
        {
            var inner = ParseOr();
            Expect(")");
            return inner;
        }
        if (t == "true") return _ => true;
        if (t == "false") return _ => false;
        if (t == "filesize") return ctx => ctx.FileSize;
        if (t == "them") throw new RuleParseException($"'them' must follow 'of' in {_rule.Name}");

        if (t is "uint8" or "uint16" or "uint32" or "uint16be" or "uint32be")
        {
            Expect("(");
            var arg = ParseOr();
            Expect(")");
            var size = t.StartsWith("uint8") ? 1 : t.StartsWith("uint16") ? 2 : 4;
            var big = t.EndsWith("be");
            return ctx => ctx.ReadInt(size, RuleContext.ToLong(arg(ctx)), big);
        }

        if (t is "any" or "all" or "none") return ParseOf(t, null);

        if (t.StartsWith('$'))
        {
            var index = FindString(t);
            if (Peek == "at")
            {
                _i++;
                var offset = ParseAdd();
                return ctx => ctx.MatchAt(index, RuleContext.ToLong(offset(ctx)));
            }
            return ctx => ctx.Count(index) > 0;
        }

        if (t.StartsWith('#'))
        {
            var index = FindString("$" + t[1..]);
            return ctx => (long)ctx.Count(index);
        }

        if (TryParseNumber(t, out var number))
        {
            if (Peek == "of") return ParseOf(null, number);
            return _ => number;
        }

        throw new RuleParseException($"'{t}' is not supported in conditions ({_rule.Name})");
    }

    private bool TryParseNumber(string t, out long value)
    {
        value = 0;
        long multiplier = 1;
        if (t.EndsWith("KB", StringComparison.OrdinalIgnoreCase)) { multiplier = 1024; t = t[..^2]; }
        else if (t.EndsWith("MB", StringComparison.OrdinalIgnoreCase)) { multiplier = 1024 * 1024; t = t[..^2]; }

        bool ok;
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            ok = long.TryParse(t[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        else
            ok = long.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

        value *= multiplier;
        return ok;
    }

    /// <summary>"any of them", "2 of ($a*)", "all of ($x, $y)", "none of them".</summary>
    private Func<RuleContext, object> ParseOf(string? quantifier, long? number)
    {
        Expect("of");
        var set = new List<int>();
        var next = Next();
        if (next == "them")
        {
            for (var k = 0; k < _rule.Strings.Count; k++) set.Add(k);
        }
        else if (next == "(")
        {
            while (true)
            {
                var item = Next();
                if (item == ")") break;
                if (item == ",") continue;
                if (!item.StartsWith('$')) throw new RuleParseException($"bad item '{item}' in 'of' list ({_rule.Name})");
                if (item.EndsWith('*'))
                {
                    var prefix = item[..^1];
                    for (var k = 0; k < _rule.Strings.Count; k++)
                    {
                        if (_rule.Strings[k].Id.StartsWith(prefix, StringComparison.Ordinal) && !set.Contains(k)) set.Add(k);
                    }
                }
                else
                {
                    var idx = FindString(item);
                    if (!set.Contains(idx)) set.Add(idx);
                }
            }
        }
        else
        {
            throw new RuleParseException($"expected 'them' or '(' after 'of' in {_rule.Name}");
        }

        if (set.Count == 0) throw new RuleParseException($"'of' list matches no strings in {_rule.Name}");

        var items = set.ToArray();
        long needed = quantifier switch
        {
            "all" => items.Length,
            "any" => 1,
            "none" => 0,
            _ => number ?? 1
        };

        if (quantifier == "none")
        {
            return ctx => items.All(k => ctx.Count(k) == 0);
        }

        return ctx =>
        {
            var hits = 0;
            foreach (var k in items)
            {
                if (ctx.Count(k) > 0 && ++hits >= needed) return true;
            }
            return hits >= needed;
        };
    }

    private int FindString(string id)
    {
        for (var k = 0; k < _rule.Strings.Count; k++)
        {
            if (_rule.Strings[k].Id == id) return k;
        }
        throw new RuleParseException($"string {id} is not defined in rule {_rule.Name}");
    }
}
