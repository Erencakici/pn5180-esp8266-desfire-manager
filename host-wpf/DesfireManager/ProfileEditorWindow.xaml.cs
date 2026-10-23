using System.Globalization;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using DesfireManager.Models;
using DesfireManager.Services;

namespace DesfireManager;

public partial class ProfileEditorWindow : Window
{
    private static readonly Regex HexPattern = new("^[0-9a-fA-F]+$", RegexOptions.Compiled);

    private readonly ProfileStore _store;

    private CardProfile _draft = CardProfile.CreateDefault();
    private string? _currentOriginalName;
    private bool _loading;

    public ProfileEditorWindow(ProfileStore store, string? selectedProfileName = null)
    {
        _store = store;

        InitializeComponent();

        Height = Math.Min(860, SystemParameters.WorkArea.Height - 40);
        Width = Math.Min(800, SystemParameters.WorkArea.Width - 40);

        RefreshProfileList(selectedProfileName);
    }

    public string? SavedProfileName { get; private set; }

    public bool ProfilesChanged { get; private set; }

    private void RefreshProfileList(string? selectedName)
    {
        _loading = true;

        var profiles = _store.Document.Profiles;

        ProfileCombo.ItemsSource = null;
        ProfileCombo.ItemsSource = profiles;

        CardProfile? selected = null;
        if (!string.IsNullOrWhiteSpace(selectedName))
        {
            selected = profiles.FirstOrDefault(profile =>
                string.Equals(profile.Name, selectedName, StringComparison.OrdinalIgnoreCase));
        }

        selected ??= profiles.FirstOrDefault();
        ProfileCombo.SelectedItem = selected;
        if (selected is null)
        {
            ProfileCombo.SelectedIndex = -1;
        }

        _loading = false;

        if (selected is null)
        {
            FillNew();
        }
        else
        {
            FillProfile(selected, selected.Name);
        }
    }

    private void ProfileCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading || ProfileCombo.SelectedItem is not CardProfile profile)
        {
            return;
        }

        FillProfile(profile, profile.Name);
    }

    private void FillProfile(CardProfile profile, string originalName)
    {
        _draft = profile.Clone();
        _currentOriginalName = originalName;
        FillForm(_draft);
        DeleteButton.IsEnabled = true;
        ShowStatus(string.Empty, EditorStatus.Neutral);
    }

    private void FillNew()
    {
        _draft = CardProfile.CreateDefault();
        _currentOriginalName = null;
        FillForm(_draft);
        DeleteButton.IsEnabled = false;
        ShowStatus(string.Empty, EditorStatus.Neutral);
        NameBox.Focus();
    }

    private void FillForm(CardProfile profile)
    {
        if (profile.Files.Count == 0)
        {
            profile.Files.Add(FileProfile.CreateDefault());
        }

        var file = profile.Files[0];
        file.CardNumber ??= new CardNumberSpec();
        var cardNumber = file.CardNumber;

        NameBox.Text = profile.Name;
        AidBox.Text = profile.Aid;
        SelectTag(AlgoBox, profile.Algo);
        KeyCountBox.Text = profile.KeyCount.ToString(CultureInfo.InvariantCulture);
        FormatCheckBox.IsChecked = profile.FormatCard;
        AppMasterBox.Password = profile.AppMasterKeyHex;
        NewMasterBox.Password = profile.NewMasterKeyHex ?? string.Empty;
        PiccMasterBox.Password = profile.PiccMasterKeyHex ?? string.Empty;
        if (DivMasterBox is not null) DivMasterBox.Password = profile.DivMasterHex ?? string.Empty;
        if (PiccNewBox is not null) PiccNewBox.Password = profile.PiccNewKeyHex ?? string.Empty;
        if (DiversifyCheckBox is not null) DiversifyCheckBox.IsChecked = profile.Diversify;
        if (PiccModeBox is not null) SelectTag(PiccModeBox, profile.PiccChangeMode);
        if (PiccTypeBox is not null) SelectTag(PiccTypeBox, profile.PiccType);

        FileIdBox.Text = file.FileId.ToString(CultureInfo.InvariantCulture);
        FileSizeBox.Text = file.Size.ToString(CultureInfo.InvariantCulture);
        CommBox.Text = file.Comm.ToString(CultureInfo.InvariantCulture);

        RBox.Text = file.R.ToString(CultureInfo.InvariantCulture);
        WBox.Text = file.W.ToString(CultureInfo.InvariantCulture);
        RwBox.Text = file.Rw.ToString(CultureInfo.InvariantCulture);
        CarBox.Text = file.Car.ToString(CultureInfo.InvariantCulture);

        RKeyBox.Password = file.RKey ?? string.Empty;
        WKeyBox.Password = file.WKey ?? string.Empty;
        RwKeyBox.Password = file.RwKey ?? string.Empty;
        CarKeyBox.Password = file.CarKey ?? string.Empty;

        CardOffsetBox.Text = cardNumber.Offset.ToString(CultureInfo.InvariantCulture);
        CardByteLenBox.Text = cardNumber.ByteLen.ToString(CultureInfo.InvariantCulture);
        SelectTag(EndianBox, cardNumber.Endian);
    }

    private void NewButton_Click(object sender, RoutedEventArgs e)
    {
        _loading = true;
        ProfileCombo.SelectedIndex = -1;
        _loading = false;

        FillNew();
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        SaveProfile();
    }

    private void SaveProfile()
    {
        if (!TryBuildProfile(out var profile, out var error))
        {
            ShowStatus(error ?? "Profil doğrulanamadı.", EditorStatus.Error);
            return;
        }

        var list = _store.Document.Profiles;
        var existingIndex = FindIndex(_currentOriginalName);

        if (_currentOriginalName is not null && existingIndex < 0)
        {
            ShowStatus("Düzenlenen profil bulunamadı.", EditorStatus.Error);
            return;
        }

        var sameNameIndex = list.FindIndex(candidate =>
            string.Equals(candidate.Name, profile.Name, StringComparison.OrdinalIgnoreCase));

        if (existingIndex >= 0 && sameNameIndex >= 0 && sameNameIndex != existingIndex)
        {
            ShowStatus("Bu isimde başka bir profil var.", EditorStatus.Error);
            return;
        }

        if (existingIndex < 0 && sameNameIndex >= 0)
        {
            var answer = MessageBox.Show(
                this,
                $"'{profile.Name}' adında bir profil zaten var. Üzerine yazılsın mı?",
                "Profil Zaten Var",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);

            if (answer != MessageBoxResult.Yes)
            {
                return;
            }
        }

        var oldName = _currentOriginalName;
        var backup = list.ToList();
        try
        {
            if (existingIndex >= 0)
            {
                list[existingIndex] = profile;
            }
            else if (sameNameIndex >= 0)
            {
                list[sameNameIndex] = profile;
            }
            else
            {
                list.Add(profile);
            }

            _store.Save();
        }
        catch (Exception ex)
        {
            list.Clear();
            list.AddRange(backup);
            ShowStatus("Kaydedilemedi: " + ex.Message, EditorStatus.Error);
            return;
        }

        ProfilesChanged = true;
        SavedProfileName = profile.Name;
        _currentOriginalName = profile.Name;

        string savedMsg;
        if (existingIndex >= 0 && !string.Equals(oldName, profile.Name, StringComparison.OrdinalIgnoreCase))
        {
            savedMsg = $"Profil yeniden adlandırıldı / renamed: '{oldName}' -> '{profile.Name}'";
        }
        else if (existingIndex >= 0 || sameNameIndex >= 0)
        {
            savedMsg = "Profil güncellendi / updated.";
        }
        else
        {
            savedMsg = "Profil eklendi / added.";
        }

        RefreshProfileList(profile.Name);
        ShowStatus(savedMsg, EditorStatus.Success);
    }

    private void DeleteButton_Click(object sender, RoutedEventArgs e)
    {
        var index = FindIndex(_currentOriginalName);
        if (index < 0)
        {
            ShowStatus("Silinecek profil bulunamadı.", EditorStatus.Error);
            return;
        }

        var list = _store.Document.Profiles;
        var profile = list[index];

        var answer = MessageBox.Show(
            this,
            $"'{profile.Name}' profili silinsin mi?",
            "Profili Sil",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        var backup = list.ToList();
        try
        {
            list.RemoveAt(index);
            _store.Save();
        }
        catch (Exception ex)
        {
            list.Clear();
            list.AddRange(backup);
            ShowStatus("Silinemedi: " + ex.Message, EditorStatus.Error);
            return;
        }

        ProfilesChanged = true;
        var next = list.Count == 0 ? null : list[Math.Min(index, list.Count - 1)];
        SavedProfileName = next?.Name;
        _currentOriginalName = null;

        RefreshProfileList(next?.Name);
        ShowStatus("Profil silindi.", EditorStatus.Success);
    }

    private bool TryBuildProfile(out CardProfile profile, out string? error)
    {
        profile = _draft.Clone();

        var name = NameBox.Text.Trim();
        if (name.Length == 0)
        {
            error = "Profil adı gerekli.";
            return false;
        }

        var aid = AidBox.Text.Trim();
        if (!IsHex(aid, 6))
        {
            error = "AID 6 karakterlik hex olmalı (örn. F20111).";
            return false;
        }

        var algo = GetTag(AlgoBox, "aes");
        if (algo != "aes" && algo != "des")
        {
            algo = "aes";
        }

        var keyLength = algo == "aes" ? 32 : 16;

        if (!TryReadInt(KeyCountBox, "Anahtar sayısı", 1, 14, out var keyCount, out error))
        {
            return false;
        }

        var appMaster = AppMasterBox.Password.Trim();
        if (!IsHex(appMaster, keyLength))
        {
            error = $"Uygulama master anahtarı {keyLength} hex karakter olmalı.";
            return false;
        }

        var newMaster = NullIfEmpty(NewMasterBox.Password);
        if (newMaster is not null && !IsHex(newMaster, keyLength))
        {
            error = $"Yeni master anahtarı {keyLength} hex karakter olmalı.";
            return false;
        }

        var piccMaster = NullIfEmpty(PiccMasterBox.Password);
        if (piccMaster is not null && !IsHex(piccMaster, 32))
        {
            error = "PICC master anahtarı 32 hex karakter (16 bayt) olmalı. / PICC master key must be 32 hex chars (16 bytes).";
            return false;
        }

        string? divMaster = null;
        if (DivMasterBox is not null)
        {
            divMaster = NullIfEmpty(DivMasterBox.Password);
            if (divMaster is not null && !IsHex(divMaster, 32))
            {
                error = "Türetme master anahtarı 32 hex karakter (16 bayt) olmalı. / Diversification master key must be 32 hex chars (16 bytes).";
                return false;
            }
        }

        string? piccNewKey = null;
        if (PiccNewBox is not null)
        {
            piccNewKey = NullIfEmpty(PiccNewBox.Password);
            var piccNewLen = 32;
            if (piccNewKey is not null && !IsHex(piccNewKey, piccNewLen))
            {
                error = $"PICC yeni anahtarı {piccNewLen} hex karakter (16 bayt) olmalı. / PICC new key must be {piccNewLen} hex chars (16 bytes).";
                return false;
            }
        }

        if (profile.Files.Count == 0)
        {
            profile.Files.Add(FileProfile.CreateDefault());
        }

        var file = profile.Files[0];

        if (!TryReadInt(FileIdBox, "Dosya ID", 0, 31, out var fileId, out error) ||
            !TryReadInt(FileSizeBox, "Dosya boyutu", 1, 65535, out var fileSize, out error) ||
            !TryReadInt(CommBox, "Haberleşme modu", 0, 3, out var comm, out error) ||
            !TryReadInt(RBox, "R yetkisi", 0, 15, out var r, out error) ||
            !TryReadInt(WBox, "W yetkisi", 0, 15, out var w, out error) ||
            !TryReadInt(RwBox, "RW yetkisi", 0, 15, out var rw, out error) ||
            !TryReadInt(CarBox, "CAR yetkisi", 0, 15, out var car, out error))
        {
            return false;
        }

        if (!TryReadKey(RKeyBox.Password, keyLength, "R anahtarı", out var rKey, out error) ||
            !TryReadKey(WKeyBox.Password, keyLength, "W anahtarı", out var wKey, out error) ||
            !TryReadKey(RwKeyBox.Password, keyLength, "RW anahtarı", out var rwKey, out error) ||
            !TryReadKey(CarKeyBox.Password, keyLength, "CAR anahtarı", out var carKey, out error))
        {
            return false;
        }

        if (!TryReadInt(CardOffsetBox, "Kart numarası başlangıcı", 0, 65535, out var offset, out error) ||
            !TryReadInt(CardByteLenBox, "Kart numarası uzunluğu", 1, 65535, out var byteLength, out error))
        {
            return false;
        }

        if (offset + byteLength > fileSize)
        {
            error = "Kart numarası dosya boyutunun dışına taşıyor.";
            return false;
        }

        var endian = GetTag(EndianBox, "big");
        if (endian != "big" && endian != "little")
        {
            endian = "big";
        }

        profile.Name = name;
        profile.Aid = aid;
        profile.Algo = algo;
        profile.KeyCount = keyCount;
        profile.FormatCard = FormatCheckBox.IsChecked == true;
        profile.AppMasterKeyHex = appMaster;
        profile.NewMasterKeyHex = newMaster;
        profile.PiccMasterKeyHex = piccMaster;
        if (DiversifyCheckBox is not null) profile.Diversify = DiversifyCheckBox.IsChecked == true;
        profile.DivMasterHex = divMaster;
        profile.PiccNewKeyHex = piccNewKey;
        if (PiccModeBox is not null) profile.PiccChangeMode = GetTag(PiccModeBox, "none");
        if (PiccTypeBox is not null) profile.PiccType = GetTag(PiccTypeBox, "des");

        file.FileId = fileId;
        file.Size = fileSize;
        file.Comm = comm;
        file.R = r;
        file.W = w;
        file.Rw = rw;
        file.Car = car;
        file.RKey = rKey;
        file.WKey = wKey;
        file.RwKey = rwKey;
        file.CarKey = carKey;

        file.CardNumber ??= new CardNumberSpec();
        file.CardNumber.Offset = offset;
        file.CardNumber.ByteLen = byteLength;
        file.CardNumber.Endian = endian;
        profile.Files[0] = file;

        error = null;
        return true;
    }

    private static bool TryReadInt(
        TextBox box,
        string label,
        int minimum,
        int maximum,
        out int value,
        out string? error)
    {
        var text = box.Text.Trim();
        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value))
        {
            error = $"{label} bir sayı olmalı.";
            return false;
        }

        if (value < minimum || value > maximum)
        {
            error = $"{label} {minimum}-{maximum} arasında olmalı.";
            return false;
        }

        error = null;
        return true;
    }

    private static bool TryReadKey(
        string input,
        int keyLength,
        string label,
        out string value,
        out string? error)
    {
        value = (input ?? string.Empty).Trim();
        if (value.Length == 0)
        {
            error = null;
            return true;
        }

        if (!IsHex(value, keyLength))
        {
            error = $"{label} {keyLength} hex karakter olmalı.";
            return false;
        }

        error = null;
        return true;
    }

    private static bool IsHex(string value, int length)
    {
        return value.Length == length && HexPattern.IsMatch(value);
    }

    private static string? NullIfEmpty(string value)
    {
        var trimmed = value.Trim();
        return trimmed.Length == 0 ? null : trimmed;
    }

    private static string GetTag(ComboBox box, string fallback)
    {
        return box.SelectedItem is ComboBoxItem { Tag: string tag } ? tag : fallback;
    }

    private static void SelectTag(ComboBox box, string? value)
    {
        foreach (var item in box.Items)
        {
            if (item is ComboBoxItem { Tag: string tag } &&
                string.Equals(tag, value, StringComparison.OrdinalIgnoreCase))
            {
                box.SelectedItem = item;
                return;
            }
        }

        box.SelectedIndex = 0;
    }

    private int FindIndex(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return -1;
        }

        var profiles = _store.Document.Profiles;
        for (var i = 0; i < profiles.Count; i++)
        {
            if (string.Equals(profiles[i].Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }

        return -1;
    }

    private enum EditorStatus
    {
        Neutral,
        Success,
        Error
    }

    private void ShowStatus(string message, EditorStatus status)
    {
        EditorStatusText.Text = message;
        EditorStatusDot.Visibility = string.IsNullOrWhiteSpace(message)
            ? Visibility.Collapsed
            : Visibility.Visible;

        var (dotKey, textKey) = status switch
        {
            EditorStatus.Success => ("StatusSuccessDot", "StatusSuccessText"),
            EditorStatus.Error => ("StatusErrorDot", "StatusErrorText"),
            _ => ("TextMuted", "TextSecondary")
        };

        EditorStatusDot.Fill = Res(dotKey);
        EditorStatusText.Foreground = Res(textKey);
    }

    private Brush Res(string key) => (Brush)FindResource(key);

    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            Close();
            e.Handled = true;
            return;
        }

        if (e.Key == Key.S && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
        {
            SaveProfile();
            e.Handled = true;
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left)
        {
            return;
        }

        try
        {
            DragMove();
        }
        catch (InvalidOperationException)
        {
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
