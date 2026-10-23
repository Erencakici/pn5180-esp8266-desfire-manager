using System.Security.Cryptography;
using System.Text;

namespace DesfireManager.Services;

public static class KeyProtector
{
    private const string Prefix = "DPAPI:";

    public static string Protect(string? plainText)
    {
        if (string.IsNullOrEmpty(plainText))
        {
            return string.Empty;
        }

        var bytes = Encoding.UTF8.GetBytes(plainText);
        var protectedBytes = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
        return Prefix + Convert.ToBase64String(protectedBytes);
    }

    public static string Unprotect(string? protectedText)
    {
        if (string.IsNullOrEmpty(protectedText))
        {
            return string.Empty;
        }

        if (!protectedText.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return protectedText;
        }

        try
        {
            var base64 = protectedText.Substring(Prefix.Length);
            var protectedBytes = Convert.FromBase64String(base64);
            var bytes = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return protectedText;
        }
    }

    public static bool IsProtected(string? text)
    {
        return !string.IsNullOrEmpty(text) && text.StartsWith(Prefix, StringComparison.Ordinal);
    }
}
