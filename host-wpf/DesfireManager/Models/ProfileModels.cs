using System.Text.Json;
using System.Text.Json.Serialization;

namespace DesfireManager.Models;

public sealed class ProfilesDocument
{
    [JsonPropertyName("profiles")]
    public List<CardProfile> Profiles { get; set; } = new();

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

public sealed class CardProfile
{
    public const string ZeroAesKey = "00000000000000000000000000000000";
    public const string ZeroDesKey = "0000000000000000";

    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("format")]
    public bool FormatCard { get; set; } = true;

    public string Aid { get; set; } = "F20111";

    public string Algo { get; set; } = "aes";

    public int KeyCount { get; set; } = 5;

    public string AppMasterKeyHex { get; set; } = ZeroAesKey;

    public string? NewMasterKeyHex { get; set; }

    public string? PiccMasterKeyHex { get; set; }

    public bool Diversify { get; set; }

    public string? DivMasterHex { get; set; }

    [JsonPropertyName("piccChangeMode")]
    public string PiccChangeMode { get; set; } = "none";

    [JsonPropertyName("piccNewKeyHex")]
    public string? PiccNewKeyHex { get; set; }

    [JsonPropertyName("piccType")]
    public string PiccType { get; set; } = "des";

    public List<FileProfile> Files { get; set; } = new();

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }

    public CardProfile Clone()
    {
        var clone = (CardProfile)MemberwiseClone();
        clone.Files = Files?.Select(file => file.Clone()).ToList() ?? new List<FileProfile>();
        clone.Extra = Extra is null
            ? null
            : new Dictionary<string, JsonElement>(Extra, StringComparer.Ordinal);
        return clone;
    }

    public static CardProfile CreateDefault(string name = "")
    {
        return new CardProfile
        {
            Name = name,
            FormatCard = true,
            Aid = "F20111",
            Algo = "aes",
            KeyCount = 5,
            AppMasterKeyHex = ZeroAesKey,
            NewMasterKeyHex = "",
            PiccMasterKeyHex = "",
            Diversify = false,
            DivMasterHex = "",
            PiccChangeMode = "none",
            PiccNewKeyHex = "",
            PiccType = "des",
            Files = new List<FileProfile> { FileProfile.CreateDefault() }
        };
    }
}

public sealed class FileProfile
{
    public int FileId { get; set; }

    public int Size { get; set; } = 14;

    public int Comm { get; set; } = 3;

    public int R { get; set; } = 3;

    public int W { get; set; }

    public int Rw { get; set; }

    public int Car { get; set; }

    public string RKey { get; set; } = string.Empty;

    public string WKey { get; set; } = string.Empty;

    public string RwKey { get; set; } = string.Empty;

    public string CarKey { get; set; } = string.Empty;

    public CardNumberSpec? CardNumber { get; set; } = new();

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }

    public FileProfile Clone()
    {
        var clone = (FileProfile)MemberwiseClone();
        clone.CardNumber = CardNumber?.Clone();
        clone.Extra = Extra is null
            ? null
            : new Dictionary<string, JsonElement>(Extra, StringComparer.Ordinal);
        return clone;
    }

    public static FileProfile CreateDefault()
    {
        return new FileProfile
        {
            FileId = 0,
            Size = 14,
            Comm = 3,
            R = 3,
            W = 0,
            Rw = 0,
            Car = 0,
            RKey = string.Empty,
            WKey = string.Empty,
            RwKey = string.Empty,
            CarKey = string.Empty,
            CardNumber = new CardNumberSpec
            {
                Offset = 4,
                ByteLen = 10,
                Endian = "big"
            }
        };
    }
}

public sealed class CardNumberSpec
{
    public int Offset { get; set; } = 4;

    public int ByteLen { get; set; } = 10;

    public string Endian { get; set; } = "big";

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }

    public CardNumberSpec Clone()
    {
        var clone = (CardNumberSpec)MemberwiseClone();
        clone.Extra = Extra is null
            ? null
            : new Dictionary<string, JsonElement>(Extra, StringComparer.Ordinal);
        return clone;
    }
}
