using System.Text.Json;

namespace DesfireManager.Services;

internal static class JsonLine
{
    public static JsonElement? Parse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(line);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static bool Has(JsonElement? root, string propertyName)
    {
        return root is { ValueKind: JsonValueKind.Object } element
               && element.TryGetProperty(propertyName, out _);
    }

    public static bool GetBool(JsonElement? root, string propertyName)
    {
        if (root is not { ValueKind: JsonValueKind.Object } element
            || !element.TryGetProperty(propertyName, out var value))
        {
            return false;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Number => value.TryGetDecimal(out var number) && number != 0,
            JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) && parsed,
            _ => false
        };
    }

    public static string? GetString(JsonElement? root, string propertyName)
    {
        if (root is not { ValueKind: JsonValueKind.Object } element
            || !element.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Null or JsonValueKind.Undefined => null,
            _ => value.GetRawText()
        };
    }

    public static bool IsOk(string? line)
    {
        return GetBool(Parse(line), "ok");
    }
}
