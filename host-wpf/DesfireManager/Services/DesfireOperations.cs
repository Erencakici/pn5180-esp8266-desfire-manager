using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using DesfireManager.Models;

namespace DesfireManager.Services;

public enum OperationStatus
{
    Success,
    Warning,
    Error
}

public readonly record struct OperationResult(string Message, OperationStatus Status);

public static class DesfireOperations
{
    private const string ZeroAesKey = "00000000000000000000000000000000";
    private const string ZeroDesKey = "0000000000000000";

    public static string? PrepareCard(SerialLink link, CardProfile profile, string cardNumber)
    {
        link.WriteLog($"===== {profile.Name} | No: {cardNumber} =====");

        if (!WaitForCard(link))
        {
            return "Kart okuyucuda değil - kartı koyup tekrar deneyin.";
        }

        var status = JsonLine.Parse(link.Send("{\"cmd\":\"status\"}", 3));
        var uid = JsonLine.GetString(status, "uid") ?? string.Empty;

        var appAlgo = IsAes(profile.Algo) ? "aes" : "iso";
        var amk = profile.AppMasterKeyHex ?? string.Empty;
        if (string.IsNullOrWhiteSpace(amk))
        {
            amk = ZeroAesKey;
        }

        var div = profile.Diversify && IsHexSet(profile.DivMasterHex) && uid.Length > 0;
        string? targetMaster = null;
        if (div)
        {
            targetMaster = DiversifyKey(profile.DivMasterHex!, uid, profile.Aid, 0);
        }
        else if (IsHexSet(profile.NewMasterKeyHex))
        {
            targetMaster = profile.NewMasterKeyHex;
        }

        if (profile.FormatCard)
        {
            TryFormat(link, profile, uid);
        }

        if (!link.SendOk(
                $"{{\"cmd\":\"create_app\",\"aid\":\"{profile.Aid}\",\"algo\":\"{profile.Algo}\",\"keys\":{profile.KeyCount}}}"))
        {
            return "Uygulama oluşturulamadı (zaten var olabilir; önce formatlayın)";
        }

        var mCands = new List<string> { amk };
        if (!string.IsNullOrWhiteSpace(targetMaster))
        {
            mCands.Add(targetMaster);
        }

        if (amk != ZeroAesKey)
        {
            mCands.Add(ZeroAesKey);
        }

        string? amkOk = null;
        foreach (var mk in mCands)
        {
            link.Send(SelectAppCommand(profile.Aid), 5);
            if (link.SendOk(AuthCommand(appAlgo, 0, mk)))
            {
                amkOk = mk;
                break;
            }
        }

        if (amkOk is null)
        {
            return "Uygulama master anahtarı doğrulanamadı (girilen / yeni / sıfır denendi)";
        }

        amk = amkOk;

        foreach (var file in profile.Files)
        {
            if (!link.SendOk(CreateFileCommand(file)))
            {
                return $"Dosya {file.FileId} oluşturulamadı";
            }

            var blob = BuildFileHex(file, cardNumber);
            if (file.W <= 13)
            {
                link.Send(AuthCommand(appAlgo, file.W, amk), 6);
            }

            if (!link.SendOk(WriteDataCommand(file.FileId, blob), 8))
            {
                return $"Dosya {file.FileId} yazılamadı";
            }
        }

        var changeAlgo = IsAes(profile.Algo) ? "aes" : "des";
        var changes = new Dictionary<int, string>();

        foreach (var file in profile.Files)
        {
            AddChange(changes, file.R, file.RKey);
            AddChange(changes, file.W, file.WKey);
            AddChange(changes, file.Rw, file.RwKey);
            AddChange(changes, file.Car, file.CarKey);
        }

        if (!string.IsNullOrWhiteSpace(targetMaster))
        {
            changes[0] = targetMaster;
        }

        if (div && IsHexSet(profile.DivMasterHex))
        {
            var readSlots = new HashSet<int>();
            foreach (var ff in profile.Files)
            {
                readSlots.Add(ff.R);
            }

            foreach (var kv in changes.ToList())
            {
                if (!readSlots.Contains(kv.Key))
                {
                    changes[kv.Key] = DiversifyKey(profile.DivMasterHex!, uid, profile.Aid, kv.Key);
                }
            }
        }

        if (changes.Count > 0)
        {
            link.Send(SelectAppCommand(profile.Aid), 5);

            string? currentMaster = null;
            if (link.SendOk(AuthCommand(appAlgo, 0, amk)))
            {
                currentMaster = amk;
            }
            else if (!string.IsNullOrWhiteSpace(targetMaster) && link.SendOk(AuthCommand(appAlgo, 0, targetMaster)))
            {
                currentMaster = targetMaster;
            }

            if (currentMaster is null)
            {
                return "Uygulama master anahtarı bilinmiyor (ne mevcut ne yeni kabul edildi)";
            }

            var slots = changes.Keys
                .OrderBy(slot => slot == 0 ? 1 : 0)
                .ThenBy(slot => slot);

            foreach (var slot in slots)
            {
                var newKey = changes[slot];

                if (slot == 0)
                {
                    if (string.Equals(currentMaster, newKey, StringComparison.OrdinalIgnoreCase))
                    {
                        link.WriteLog("  slot 0 zaten ayarlı, atlandı");
                        continue;
                    }

                    link.Send(SelectAppCommand(profile.Aid), 5);
                    if (!link.SendOk(AuthCommand(appAlgo, 0, currentMaster)))
                    {
                        return "Master değişimi için auth başarısız";
                    }

                    if (!link.SendOk(ChangeKeyCommand(0, changeAlgo, newKey, currentMaster), 8))
                    {
                        return "Master anahtarı değiştirilemedi";
                    }

                    currentMaster = newKey;
                    continue;
                }

                link.Send(SelectAppCommand(profile.Aid), 5);
                string? currentKey = null;
                if (link.SendOk(AuthCommand(appAlgo, slot, ZeroAesKey)))
                {
                    currentKey = ZeroAesKey;
                }
                else
                {
                    link.Send(SelectAppCommand(profile.Aid), 5);
                    if (link.SendOk(AuthCommand(appAlgo, slot, newKey)))
                    {
                        currentKey = newKey;
                    }
                }

                if (string.Equals(currentKey, newKey, StringComparison.OrdinalIgnoreCase))
                {
                    link.WriteLog($"  slot {slot} zaten ayarlı, atlandı");
                    continue;
                }

                if (currentKey is null)
                {
                    return $"Slot {slot} mevcut anahtarı bilinmiyor (ne sıfır ne hedef)";
                }

                link.Send(SelectAppCommand(profile.Aid), 5);
                if (!link.SendOk(AuthCommand(appAlgo, 0, currentMaster)))
                {
                    return $"Slot {slot} değişimi için master auth başarısız";
                }

                if (!link.SendOk(ChangeKeyCommand(slot, changeAlgo, newKey, currentKey), 8))
                {
                    return $"Anahtar {slot} değiştirilemedi";
                }
            }
        }

        var piccTarget = PiccTargetKey(profile, uid);
        if (piccTarget is not null)
        {
            var ptype = string.Equals(profile.PiccType, "aes", StringComparison.OrdinalIgnoreCase) ? "aes" : "des";
            var tAuth = ptype == "aes" ? "aes" : "iso";
            var tChange = ptype == "aes" ? "aes" : "2k3des";

            string? curAlgo = null;
            string? curKey = null;
            foreach (var cc in new[] { ("iso", ZeroAesKey), ("aes", ZeroAesKey), ("iso", piccTarget), ("aes", piccTarget) })
            {
                link.Send("{\"cmd\":\"select_app\",\"aid\":\"000000\"}", 5);
                if (link.SendOk(AuthCommand(cc.Item1, 0, cc.Item2)))
                {
                    curAlgo = cc.Item1;
                    curKey = cc.Item2;
                    break;
                }
            }

            if (curAlgo is null)
            {
                return "PICC master anahtarı/tipi bilinmiyor (sıfır ve hedef denendi)";
            }

            var already = string.Equals(curKey, piccTarget, StringComparison.OrdinalIgnoreCase) && string.Equals(curAlgo, tAuth, StringComparison.OrdinalIgnoreCase);
            if (!already)
            {
                link.Send("{\"cmd\":\"select_app\",\"aid\":\"000000\"}", 5);
                if (!link.SendOk(AuthCommand(curAlgo, 0, curKey!)))
                {
                    return "PICC master auth başarısız";
                }

                if (!link.SendOk($"{{\"cmd\":\"change_key\",\"keyNo\":0,\"algo\":\"{tChange}\",\"newKey\":\"{piccTarget}\",\"oldKey\":\"{piccTarget}\",\"typeChange\":1}}", 8))
                {
                    return "PICC master değiştirilemedi";
                }

                link.WriteLog($"  PICC master değiştirildi (tip={ptype}, artık sıfır ile format yapılamaz)");
            }
        }
        else if (string.Equals(profile.PiccChangeMode, "diversified", StringComparison.OrdinalIgnoreCase) && !IsHexSet(profile.DivMasterHex))
        {
            link.WriteLog("  (PICC türetme için 'Türetme master' boş - PICC master değişmedi)");
        }

        return null;
    }

    public static OperationResult ReadCard(SerialLink link, CardProfile profile)
    {
        if (!WaitForCard(link))
        {
            return new OperationResult("Kart okuyucuda değil", OperationStatus.Warning);
        }

        var appAlgo = IsAes(profile.Algo) ? "aes" : "iso";
        var file = profile.Files.FirstOrDefault();
        if (file is null)
        {
            return new OperationResult("Profilde dosya tanımlı değil", OperationStatus.Error);
        }

        var readKey = IsHexSet(file.RKey) ? file.RKey : profile.AppMasterKeyHex;
        link.WriteLog($"===== OKU: {profile.Name} (slot {file.R}) =====");
        link.Send(SelectAppCommand(profile.Aid), 5);

        if (!link.SendOk(AuthCommand(appAlgo, file.R, readKey)))
        {
            return new OperationResult(
                $"Okuma anahtarı doğrulanamadı (slot {file.R})",
                OperationStatus.Error);
        }

        var read = JsonLine.Parse(link.Send(
            $"{{\"cmd\":\"read_data\",\"file\":{file.FileId},\"offset\":0,\"length\":{file.Size}}}", 8));

        if (!JsonLine.GetBool(read, "ok"))
        {
            return new OperationResult(
                "Okuma başarısız (dosya şifreli olabilir - firmware güncel mi?)",
                OperationStatus.Error);
        }

        var hex = JsonLine.GetString(read, "bytes") ?? string.Empty;
        var number = ParseCardNum(file, hex);
        var crcNote = JsonLine.Has(read, "crcOk") && !JsonLine.GetBool(read, "crcOk")
            ? "  (CRC doğrulanmadı)"
            : string.Empty;
        var text = JsonLine.GetString(read, "text") ?? string.Empty;

        link.WriteLog($"  bytes={hex}  text={text}");
        return new OperationResult($"KART NO: {number}{crcNote}", OperationStatus.Success);
    }

    public static OperationResult FormatCard(SerialLink link, CardProfile profile)
    {
        if (!WaitForCard(link))
        {
            return new OperationResult("Kart okuyucuda değil / No card", OperationStatus.Warning);
        }

        var status = JsonLine.Parse(link.Send("{\"cmd\":\"status\"}", 3));
        var uid = JsonLine.GetString(status, "uid") ?? string.Empty;
        link.WriteLog($"===== FORMAT: {profile.Name} =====");

        return TryFormat(link, profile, uid)
            ? new OperationResult("FORMATLANDI / FORMATTED - kart boş / card empty", OperationStatus.Success)
            : new OperationResult("Format başarısız / Format failed (PICC master?)", OperationStatus.Error);
    }

    private static bool TryFormat(SerialLink link, CardProfile profile, string uid)
    {
        link.Send("{\"cmd\":\"select_app\",\"aid\":\"000000\"}", 5);

        var piccTargetForFormat = PiccTargetKey(profile, uid);
        var candidates = new List<(string Algo, string Key)>();
        if (piccTargetForFormat is not null)
        {
            candidates.Add(("aes", piccTargetForFormat));
            candidates.Add(("iso", piccTargetForFormat));
        }

        if (IsHexSet(profile.PiccMasterKeyHex))
        {
            var pk = profile.PiccMasterKeyHex!;
            candidates.Add(("aes", pk));
            candidates.Add(("iso", pk));
        }

        candidates.Add(("iso", ZeroAesKey));
        candidates.Add(("aes", ZeroAesKey));
        candidates.Add(("des", ZeroDesKey));

        var piccOpened = false;
        foreach (var candidate in candidates)
        {
            var auth = JsonLine.Parse(link.Send(AuthCommand(candidate.Algo, 0, candidate.Key), 6));
            if (JsonLine.GetBool(auth, "authenticated"))
            {
                piccOpened = true;
                break;
            }
        }

        if (!piccOpened)
        {
            link.WriteLog("  (PICC master açılamadı; kart boş olabilir)");
            return false;
        }

        var format = JsonLine.Parse(link.Send("{\"cmd\":\"format\",\"confirm\":true}", 8));
        var token = JsonLine.GetString(format, "token");
        if (string.IsNullOrEmpty(token))
        {
            link.WriteLog("  (format token alınamadı)");
            return false;
        }

        return link.SendOk($"{{\"cmd\":\"format\",\"confirm\":true,\"token\":\"{token}\"}}", 12);
    }

    private static string? PiccTargetKey(CardProfile profile, string uid)
    {
        var mode = profile.PiccChangeMode ?? "none";
        if (string.Equals(mode, "fixed", StringComparison.OrdinalIgnoreCase))
        {
            if (IsHexSet(profile.PiccNewKeyHex))
            {
                return profile.PiccNewKeyHex;
            }
        }
        else if (string.Equals(mode, "diversified", StringComparison.OrdinalIgnoreCase))
        {
            if (IsHexSet(profile.DivMasterHex) && uid.Length > 0)
            {
                return DiversifyKey(profile.DivMasterHex!, uid, "000000", 0);
            }
        }

        return null;
    }

    private static string DiversifyKey(string masterHex, string uidHex, string aidHex, int slot)
    {
        var key = HexToBytes(masterHex);
        var uid = HexToBytes(uidHex);
        var aid = HexToBytes(aidHex);
        var msg = new List<byte> { 0x01 };
        msg.AddRange(uid);
        msg.AddRange(aid);
        msg.Add((byte)slot);
        return BytesToHex(AesCmac(key, msg.ToArray()));
    }

    private static byte[] AesCmac(byte[] key, byte[] msg)
    {
        var zero = new byte[16];
        var L = AesEcbBlock(key, zero);
        var K1 = LShift1(L);
        if ((L[0] & 0x80) != 0) K1[15] ^= 0x87;
        var K2 = LShift1(K1);
        if ((K1[0] & 0x80) != 0) K2[15] ^= 0x87;

        var len = msg.Length;
        var complete = len > 0 && len % 16 == 0;
        var n = len == 0 ? 1 : (int)Math.Ceiling(len / 16.0);
        var lastStart = (n - 1) * 16;
        var last = new byte[16];
        if (complete)
        {
            for (var i = 0; i < 16; i++) last[i] = (byte)(msg[lastStart + i] ^ K1[i]);
        }
        else
        {
            var pad = new byte[16];
            var rem = len - lastStart;
            Array.Copy(msg, lastStart, pad, 0, rem);
            pad[rem] = 0x80;
            for (var i = 0; i < 16; i++) last[i] = (byte)(pad[i] ^ K2[i]);
        }

        var X = new byte[16];
        for (var j = 0; j < n - 1; j++)
        {
            var blk = new byte[16];
            for (var i = 0; i < 16; i++) blk[i] = (byte)(X[i] ^ msg[j * 16 + i]);
            X = AesEcbBlock(key, blk);
        }

        var fin = new byte[16];
        for (var i = 0; i < 16; i++) fin[i] = (byte)(X[i] ^ last[i]);
        return AesEcbBlock(key, fin);
    }

    private static byte[] AesEcbBlock(byte[] key, byte[] block)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(block, 0, 16);
    }

    private static byte[] LShift1(byte[] b)
    {
        var o = new byte[16];
        var carry = 0;
        for (var i = 15; i >= 0; i--)
        {
            var v = ((b[i] << 1) | carry);
            o[i] = (byte)(v & 0xFF);
            carry = (v >> 8) & 1;
        }
        return o;
    }

    private static byte[] HexToBytes(string h)
    {
        h = (h ?? string.Empty).Trim();
        var n = h.Length / 2;
        var b = new byte[n];
        for (var i = 0; i < n; i++)
        {
            b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
        }
        return b;
    }

    private static string BytesToHex(byte[] b)
    {
        return Convert.ToHexString(b).ToLowerInvariant();
    }

    public static string NumToHex(string? decimalText, int byteLength, string? endian)
    {
        if (byteLength <= 0)
        {
            return string.Empty;
        }

        if (!BigInteger.TryParse(decimalText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            || value < BigInteger.Zero)
        {
            return new string('0', byteLength * 2);
        }

        var bytes = new byte[byteLength];
        for (var index = byteLength - 1; index >= 0; index--)
        {
            bytes[index] = (byte)(int)(value % 256);
            value /= 256;
        }

        if (string.Equals(endian, "little", StringComparison.OrdinalIgnoreCase))
        {
            Array.Reverse(bytes);
        }

        return Convert.ToHexString(bytes);
    }

    public static bool IsHexSet(string? hex)
    {
        if (hex is null)
        {
            return false;
        }

        var trimmed = hex.Trim();
        return trimmed.Length > 0 && trimmed.TrimStart('0').Length > 0;
    }

    public static string ParseCardNum(FileProfile file, string hex)
    {
        if (file.CardNumber is null)
        {
            return hex;
        }

        var offset = file.CardNumber.Offset;
        var byteLength = file.CardNumber.ByteLen;
        if (hex.Length < (offset + byteLength) * 2)
        {
            return "?";
        }

        var slice = hex.Substring(offset * 2, byteLength * 2);
        var bytes = new byte[byteLength];
        for (var index = 0; index < byteLength; index++)
        {
            bytes[index] = Convert.ToByte(slice.Substring(index * 2, 2), 16);
        }

        if (string.Equals(file.CardNumber.Endian, "little", StringComparison.OrdinalIgnoreCase))
        {
            Array.Reverse(bytes);
        }

        var value = BigInteger.Zero;
        foreach (var item in bytes)
        {
            value = (value * 256) + item;
        }

        return value.ToString(CultureInfo.InvariantCulture);
    }

    public static string BuildFileHex(FileProfile file, string cardNumber)
    {
        var bytes = new byte[file.Size];
        if (file.CardNumber is not null)
        {
            var byteLength = file.CardNumber.ByteLen;
            var hex = NumToHex(cardNumber, byteLength, file.CardNumber.Endian);
            var offset = file.CardNumber.Offset;
            for (var index = 0; index < byteLength; index++)
            {
                bytes[offset + index] = Convert.ToByte(hex.Substring(index * 2, 2), 16);
            }
        }

        return Convert.ToHexString(bytes);
    }

    private static bool WaitForCard(SerialLink link)
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var status = JsonLine.Parse(link.Send("{\"cmd\":\"status\"}", 3));
            if (JsonLine.GetBool(status, "card"))
            {
                return true;
            }

            Thread.Sleep(300);
        }

        return false;
    }

    private static bool IsAes(string? algo)
    {
        return string.Equals(algo, "aes", StringComparison.OrdinalIgnoreCase);
    }

    private static void AddChange(Dictionary<int, string> changes, int slot, string? key)
    {
        if (IsHexSet(key))
        {
            changes[slot] = key!;
        }
    }

    private static string SelectAppCommand(string aid)
    {
        return $"{{\"cmd\":\"select_app\",\"aid\":\"{aid}\"}}";
    }

    private static string AuthCommand(string algo, int keyNo, string key)
    {
        return $"{{\"cmd\":\"auth\",\"algo\":\"{algo}\",\"keyNo\":{keyNo},\"key\":\"{key}\"}}";
    }

    private static string CreateFileCommand(FileProfile file)
    {
        return $"{{\"cmd\":\"create_file\",\"file\":{file.FileId},\"size\":{file.Size},\"comm\":{file.Comm},\"rw\":{file.Rw},\"car\":{file.Car},\"r\":{file.R},\"w\":{file.W}}}";
    }

    private static string WriteDataCommand(int fileId, string hex)
    {
        return $"{{\"cmd\":\"write_data\",\"file\":{fileId},\"offset\":0,\"hex\":\"{hex}\"}}";
    }

    private static string ChangeKeyCommand(int keyNo, string algo, string newKey, string oldKey)
    {
        return $"{{\"cmd\":\"change_key\",\"keyNo\":{keyNo},\"algo\":\"{algo}\",\"newKey\":\"{newKey}\",\"oldKey\":\"{oldKey}\"}}";
    }
}
