using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using DesfireManager.Models;

namespace DesfireManager.Services;

public sealed class ProfileStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public ProfileStore(string? filePath = null)
    {
        FilePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "DesfireManager",
            "profiles.json");
        Load();
    }

    public string FilePath { get; }

    public ProfilesDocument Document { get; private set; } = new();

    public IReadOnlyList<CardProfile> Profiles => Document.Profiles;

    public void Load()
    {
        var directory = Path.GetDirectoryName(FilePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        if (!File.Exists(FilePath))
        {
            var seed = Path.Combine(AppContext.BaseDirectory, "profiles.json");
            if (File.Exists(seed))
            {
                File.Copy(seed, FilePath);
            }
            else
            {
                Document = new ProfilesDocument();
                WriteDocument(Document);
                return;
            }
        }

        try
        {
            var json = File.ReadAllText(FilePath, Encoding.UTF8);
            var document = JsonSerializer.Deserialize<ProfilesDocument>(json, JsonOptions)
                           ?? new ProfilesDocument();
            Normalize(document);
            var unprotected = new ProfilesDocument
            {
                Extra = document.Extra is null ? null : new Dictionary<string, JsonElement>(document.Extra, StringComparer.Ordinal),
                Profiles = document.Profiles.Select(p => UnprotectProfile(p)).ToList()
            };
            Document = unprotected;
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(
                $"Profil dosyası okunamadı: {FilePath}", ex);
        }
    }

    public void Save()
    {
        WriteDocument(Document);
    }

    public CardProfile? FindByName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        return Document.Profiles.FirstOrDefault(profile =>
            string.Equals(profile.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    private void WriteDocument(ProfilesDocument document)
    {
        var directory = Path.GetDirectoryName(FilePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var saveDoc = new ProfilesDocument
        {
            Extra = document.Extra is null ? null : new Dictionary<string, JsonElement>(document.Extra, StringComparer.Ordinal),
            Profiles = document.Profiles.Select(p => ProtectProfile(p)).ToList()
        };

        var json = JsonSerializer.Serialize(saveDoc, JsonOptions);
        var temporaryPath = FilePath + ".tmp";
        File.WriteAllText(temporaryPath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(temporaryPath, FilePath, overwrite: true);
    }

    private static CardProfile ProtectProfile(CardProfile source)
    {
        var profile = source.Clone();
        profile.AppMasterKeyHex = KeyProtector.Protect(profile.AppMasterKeyHex);
        profile.NewMasterKeyHex = KeyProtector.Protect(profile.NewMasterKeyHex);
        profile.PiccMasterKeyHex = KeyProtector.Protect(profile.PiccMasterKeyHex);
        profile.DivMasterHex = KeyProtector.Protect(profile.DivMasterHex);
        profile.PiccNewKeyHex = KeyProtector.Protect(profile.PiccNewKeyHex);

        foreach (var file in profile.Files)
        {
            file.RKey = KeyProtector.Protect(file.RKey);
            file.WKey = KeyProtector.Protect(file.WKey);
            file.RwKey = KeyProtector.Protect(file.RwKey);
            file.CarKey = KeyProtector.Protect(file.CarKey);
        }

        return profile;
    }

    private static CardProfile UnprotectProfile(CardProfile source)
    {
        var profile = source.Clone();
        profile.AppMasterKeyHex = KeyProtector.Unprotect(profile.AppMasterKeyHex);
        profile.NewMasterKeyHex = KeyProtector.Unprotect(profile.NewMasterKeyHex);
        profile.PiccMasterKeyHex = KeyProtector.Unprotect(profile.PiccMasterKeyHex);
        profile.DivMasterHex = KeyProtector.Unprotect(profile.DivMasterHex);
        profile.PiccNewKeyHex = KeyProtector.Unprotect(profile.PiccNewKeyHex);

        foreach (var file in profile.Files)
        {
            file.RKey = KeyProtector.Unprotect(file.RKey);
            file.WKey = KeyProtector.Unprotect(file.WKey);
            file.RwKey = KeyProtector.Unprotect(file.RwKey);
            file.CarKey = KeyProtector.Unprotect(file.CarKey);
        }

        return profile;
    }

    private static void Normalize(ProfilesDocument document)
    {
        document.Profiles ??= new List<CardProfile>();

        foreach (var profile in document.Profiles)
        {
            profile.Name ??= string.Empty;
            profile.Aid ??= string.Empty;
            profile.Algo ??= "aes";
            profile.AppMasterKeyHex ??= string.Empty;
            profile.NewMasterKeyHex ??= string.Empty;
            profile.PiccMasterKeyHex ??= string.Empty;
            profile.DivMasterHex ??= string.Empty;
            profile.PiccNewKeyHex ??= string.Empty;
            if (string.IsNullOrWhiteSpace(profile.PiccChangeMode))
            {
                profile.PiccChangeMode = "none";
            }

            if (string.IsNullOrWhiteSpace(profile.PiccType))
            {
                profile.PiccType = "des";
            }

            profile.Files ??= new List<FileProfile>();

            foreach (var file in profile.Files)
            {
                file.RKey ??= string.Empty;
                file.WKey ??= string.Empty;
                file.RwKey ??= string.Empty;
                file.CarKey ??= string.Empty;
                if (file.CardNumber is not null)
                {
                    file.CardNumber.Endian ??= "big";
                }
            }
        }
    }
}
