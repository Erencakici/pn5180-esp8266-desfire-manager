using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using DesfireManager.Models;
using DesfireManager.Services;
using Microsoft.Win32;

namespace DesfireManager;

public partial class MainWindow : Window
{
    private readonly SerialLink _serial = new();
    private readonly ProfileStore? _profileStore;

    private Task<bool>? _connectTask;
    private bool _busy;
    private bool _closing;
    private readonly ObservableCollection<BatchItem> _batchItems = new();
    private int _currentBatchIndex = -1;
    private bool _batchMode;
    private List<string> _batchLines = new();
    private string? _batchFilePath;
    private string? _lastWrittenUid;

    public class BatchItem
    {
        public string CardNumber { get; set; } = string.Empty;
        public int LineIndex { get; set; } = -1;
        public string Status { get; set; } = "Beklemede / Pending";
        public string Time { get; set; } = string.Empty;
    }

    public MainWindow()
    {
        InitializeComponent();

        _serial.MessageLogged += OnSerialMessage;

        try
        {
            _profileStore = new ProfileStore();
            RefreshProfileCombo(null);
        }
        catch (Exception ex)
        {
            AppendLog("Profiller yüklenemedi: " + ex.Message);
            SetStatus("Profil dosyası okunamadı", StatusKind.Error);
        }
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        CardNumberBox.Focus();
        await EnsureConnectedAsync();
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        _closing = true;
        _serial.Dispose();
    }

    private async Task<bool> EnsureConnectedAsync(bool force = false)
    {
        if (!force && _serial.IsConnected)
        {
            return true;
        }

        if (_connectTask is not null)
        {
            return await _connectTask;
        }

        _connectTask = ConnectCoreAsync();
        try
        {
            return await _connectTask;
        }
        finally
        {
            _connectTask = null;
        }
    }

    private async Task<bool> ConnectCoreAsync()
    {
        ShowConnecting();
        try
        {
            var ok = await Task.Run(_serial.Connect);
            if (ok)
            {
                ShowConnected(_serial.PortName);
            }
            else
            {
                ShowDisconnected();
            }

            return ok;
        }
        catch (Exception ex)
        {
            AppendLog("Bağlantı hatası / Connection error: " + ex.Message);
            ShowDisconnected();
            return false;
        }
    }

    private void ShowConnecting()
    {
        ConnectionText.Text = "Bağlanıyor / Connecting...";
        ConnectionText.Foreground = Res("TextPrimary");
        SetConnectionDot(Res("Amber"));

        ConnectionGlow.Opacity = 0.3;
        var pulse = new DoubleAnimation(0.15, 0.55, TimeSpan.FromMilliseconds(900))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever
        };
        ConnectionGlow.BeginAnimation(OpacityProperty, pulse);
    }

    private void ShowConnected(string? port)
    {
        ConnectionGlow.BeginAnimation(OpacityProperty, null);
        ConnectionGlow.Opacity = 0.3;

        ConnectionText.Text = string.IsNullOrWhiteSpace(port)
            ? "Bağlandı / Connected"
            : $"Bağlandı / Connected: {port}";
        ConnectionText.Foreground = Res("TextPrimary");
        SetConnectionDot(Res("Green"));
    }

    private void ShowDisconnected()
    {
        ConnectionGlow.BeginAnimation(OpacityProperty, null);
        ConnectionGlow.Opacity = 0.3;

        ConnectionText.Text = "Cihaz yok (okuyucu takılı / konsol açık mı?) / No device";
        ConnectionText.Foreground = Res("TextSecondary");
        SetConnectionDot(Res("Red"));
    }

    private void SetConnectionDot(Brush brush)
    {
        ConnectionDot.Fill = brush;
        ConnectionGlow.Stroke = brush;
    }

    private async void ReconnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        await EnsureConnectedAsync(force: true);
    }

    private async void PrepareButton_Click(object sender, RoutedEventArgs e)
    {
        await PrepareAsync();
    }

    private async void CardNumberBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter)
        {
            return;
        }

        e.Handled = true;
        await PrepareAsync();
    }

    private async Task PrepareAsync()
    {
        if (_busy)
        {
            return;
        }

        if (ProfileCombo.SelectedItem is not CardProfile profile)
        {
            SetStatus("Önce bir profil seçin", StatusKind.Warning);
            ProfileCombo.Focus();
            return;
        }

        var number = CardNumberBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(number))
        {
                SetStatus("Veri girin / Enter data", StatusKind.Warning);
            CardNumberBox.Focus();
            return;
        }

        if (!ConfirmPiccIfNeeded(profile))
        {
            return;
        }

        if (!await EnsureConnectedAsync())
        {
            SetStatus("Bağlantı yok. Okuyucuyu kontrol edin.", StatusKind.Error);
            return;
        }

        BeginBusy();
            SetStatus("Kart hazırlanıyor... / Preparing...", StatusKind.Neutral);

        string? error;
        try
        {
            error = await Task.Run(() => DesfireOperations.PrepareCard(_serial, profile, number));
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
        finally
        {
            EndBusy();
        }

        if (_closing)
        {
            return;
        }

        if (error is null)
        {
            SetStatus($"HAZIR / READY  -  {number}  yazıldı / written. Sonraki kartı koyun / Put next card.", StatusKind.Success);
            CardNumberBox.Focus();
            CardNumberBox.SelectAll();
        }
        else
        {
            SetStatus("HATA / ERROR: " + error, StatusKind.Error);
        }
    }

    private async void ReadButton_Click(object sender, RoutedEventArgs e)
    {
        await ReadAsync();
    }

    private async Task ReadAsync()
    {
        if (_busy)
        {
            return;
        }

        if (ProfileCombo.SelectedItem is not CardProfile profile)
        {
            SetStatus("Önce bir profil seçin", StatusKind.Warning);
            ProfileCombo.Focus();
            return;
        }

        if (!await EnsureConnectedAsync())
        {
            SetStatus("Bağlantı yok. Okuyucuyu kontrol edin.", StatusKind.Error);
            return;
        }

        BeginBusy();
        SetStatus("Kart okunuyor...", StatusKind.Neutral);

        OperationResult result;
        try
        {
            result = await Task.Run(() => DesfireOperations.ReadCard(_serial, profile));
        }
        catch (Exception ex)
        {
                result = new OperationResult("HATA / ERROR: " + ex.Message, OperationStatus.Error);
        }
        finally
        {
            EndBusy();
        }

        if (_closing)
        {
            return;
        }

        var kind = result.Status switch
        {
            OperationStatus.Success => StatusKind.Success,
            OperationStatus.Warning => StatusKind.Warning,
            _ => StatusKind.Error
        };

        SetStatus(result.Message, kind);
    }

    private async void FormatButton_Click(object sender, RoutedEventArgs e)
    {
        await FormatAsync();
    }

    private async Task FormatAsync()
    {
        if (_busy)
        {
            return;
        }

        if (ProfileCombo.SelectedItem is not CardProfile profile)
        {
            SetStatus("Önce bir profil seçin / Select a profile", StatusKind.Warning);
            ProfileCombo.Focus();
            return;
        }

        var confirm = MessageBox.Show(
            this,
            "Kart TAMAMEN silinecek (format).\nThe card will be COMPLETELY erased (format).\n\nDevam edilsin mi? / Continue?",
            "Format",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        if (!await EnsureConnectedAsync())
        {
            SetStatus("Bağlantı yok / No connection", StatusKind.Error);
            return;
        }

        BeginBusy();
        SetStatus("Formatlanıyor... / Formatting...", StatusKind.Neutral);

        OperationResult result;
        try
        {
            result = await Task.Run(() => DesfireOperations.FormatCard(_serial, profile));
        }
        catch (Exception ex)
        {
            result = new OperationResult("HATA / ERROR: " + ex.Message, OperationStatus.Error);
        }
        finally
        {
            EndBusy();
        }

        if (_closing)
        {
            return;
        }

        var kind = result.Status switch
        {
            OperationStatus.Success => StatusKind.Success,
            OperationStatus.Warning => StatusKind.Warning,
            _ => StatusKind.Error
        };

        SetStatus(result.Message, kind);
    }

    private void InfoButton_Click(object sender, RoutedEventArgs e)
    {
        var info = new InfoWindow { Owner = this };
        info.ShowDialog();
    }

    private bool _piccAcknowledged;

    private bool ConfirmPiccIfNeeded(CardProfile profile)
    {
        if (string.Equals(profile.PiccChangeMode, "none", StringComparison.OrdinalIgnoreCase) || _piccAcknowledged)
        {
            return true;
        }

        var answer = MessageBox.Show(
            this,
            "DİKKAT: Bu profil PICC (kart) master anahtarını değiştirir. Bu işlem GERİ ALINAMAZ; anahtar kaybı veya yanlış değer kartı KALICI olarak kilitler.\n\nWARNING: This profile changes the PICC (card) master key. This is IRREVERSIBLE; a lost or wrong key PERMANENTLY bricks the card.\n\nDevam edilsin mi? / Continue?",
            "PICC Master",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer == MessageBoxResult.Yes)
        {
            _piccAcknowledged = true;
            return true;
        }

        return false;
    }

    private void BeginBusy()
    {
        _busy = true;
        Cursor = Cursors.Wait;

        PrepareButton.IsEnabled = false;
        ReadButton.IsEnabled = false;
        FormatButton.IsEnabled = false;
        ReconnectButton.IsEnabled = false;
        ManageProfilesButton.IsEnabled = false;
        ProfileCombo.IsEnabled = false;
        CardNumberBox.IsEnabled = false;
    }

    private void EndBusy()
    {
        _busy = false;
        Cursor = Cursors.Arrow;

        PrepareButton.IsEnabled = true;
        ReadButton.IsEnabled = true;
        FormatButton.IsEnabled = true;
        ReconnectButton.IsEnabled = true;
        ManageProfilesButton.IsEnabled = true;
        ProfileCombo.IsEnabled = true;
        CardNumberBox.IsEnabled = true;
    }

    private void ManageProfilesButton_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _profileStore is null)
        {
            return;
        }

        var selectedName = (ProfileCombo.SelectedItem as CardProfile)?.Name;
        var editor = new ProfileEditorWindow(_profileStore, selectedName)
        {
            Owner = this
        };

        editor.ShowDialog();
        RefreshProfileCombo(editor.SavedProfileName ?? selectedName);
    }

    private void ImportBatchButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Metin Dosyası (*.txt)|*.txt|Tüm Dosyalar (*.*)|*.*",
            Title = "Veri Listesi İçe Aktar / Import Data List"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            _batchLines = File.ReadAllLines(dialog.FileName, Encoding.UTF8).ToList();
            _batchFilePath = dialog.FileName;
            _lastWrittenUid = null;
            _batchItems.Clear();
            for (var i = 0; i < _batchLines.Count; i++)
            {
                var value = StripInlineComment(_batchLines[i]);
                if (value.Length == 0)
                {
                    continue;
                }
                _batchItems.Add(new BatchItem { CardNumber = value, LineIndex = i });
            }

            var skipped = _batchLines.Count(l => l.TrimStart().StartsWith("# OK", StringComparison.OrdinalIgnoreCase));
            SetStatus($"{_batchItems.Count} veri yüklendi, {skipped} tamamlanmış atlandı / {_batchItems.Count} loaded, {skipped} done skipped", StatusKind.Success);
        }
        catch (Exception ex)
        {
            SetStatus("HATA / ERROR: " + ex.Message, StatusKind.Error);
        }
    }

    private const string SampleBatchContent =
        "# PN5180 ESP8266 DESFire Manager - toplu veri listesi / batch data list\r\n" +
        "# Her satir bir karta yazilacak veridir; her satirda tek deger.\r\n" +
        "# One value per line (the data written to each card).\r\n" +
        "# '#' ile baslayan satirlar ve bos satirlar atlanir / '#' and blank lines are skipped.\r\n" +
        "#\r\n" +
        "# Ornek / Example:\r\n" +
        "276968576\r\n" +
        "276968577\r\n" +
        "276968578\r\n";

    private void DownloadSampleButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Örnek Liste Kaydet / Save Sample List",
            Filter = "Metin Dosyası (*.txt)|*.txt|Tüm Dosyalar (*.*)|*.*",
            FileName = "ornek-liste.txt"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            File.WriteAllText(dialog.FileName, SampleBatchContent, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            SetStatus("Örnek liste kaydedildi / Sample list saved", StatusKind.Success);
        }
        catch (Exception ex)
        {
            SetStatus("HATA / ERROR: " + ex.Message, StatusKind.Error);
        }
    }

    private async void StartBatchButton_Click(object sender, RoutedEventArgs e)
    {
        if (_batchItems.Count == 0)
        {
            SetStatus("Önce liste içe aktarın / Import list first", StatusKind.Warning);
            return;
        }

        if (ProfileCombo.SelectedItem is not CardProfile profile)
        {
            SetStatus("Profil seçin / Select profile", StatusKind.Warning);
            ProfileCombo.Focus();
            return;
        }

        if (_busy || _batchMode)
        {
            return;
        }

        if (!ConfirmPiccIfNeeded(profile))
        {
            return;
        }

        _batchMode = true;
        _currentBatchIndex = 0;
        StartBatchButton.IsEnabled = false;
        ImportBatchButton.IsEnabled = false;

        try
        {
            if (!await EnsureConnectedAsync())
            {
                SetStatus("Bağlantı yok / No connection", StatusKind.Error);
                return;
            }

            _lastWrittenUid = null;
            var done = 0;
            var failed = 0;

            for (int i = 0; i < _batchItems.Count; i++)
            {
                if (_closing) break;
                _currentBatchIndex = i;
                var item = _batchItems[i];

                string? uid = null;
                while (!_closing)
                {
                    var candidate = await WaitForDifferentCardAsync(_lastWrittenUid, i + 1, _batchItems.Count, item.CardNumber);
                    if (candidate is null)
                    {
                        break;
                    }

                    // Son güvenlik: yazimdan HEMEN once UID'yi tekrar oku. Ayni kart ya da
                    // baglanti kopmasi durumunda ASLA yazma, farkli kart beklenir.
                    var nowUid = await ReadCurrentUidAsync();
                    if (nowUid is not null && !string.Equals(nowUid, _lastWrittenUid, StringComparison.OrdinalIgnoreCase))
                    {
                        uid = nowUid;
                        break;
                    }

                    SetStatus($"[{i + 1}/{_batchItems.Count}] Ayni kart — cikarip BASKA KART okutun / same card, tap a DIFFERENT one", StatusKind.Warning);
                    await Task.Delay(500);
                }

                if (uid is null) break;

                item.Status = "İşleniyor / Processing";
                SetStatus($"[{i + 1}/{_batchItems.Count}] {item.CardNumber} yazılıyor / writing...", StatusKind.Neutral);

                BeginBusy();
                string? error = null;
                try
                {
                    error = await Task.Run(() => DesfireOperations.PrepareCard(_serial, profile, item.CardNumber));
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                }
                finally
                {
                    EndBusy();
                }

                _lastWrittenUid = uid;

                if (error is null)
                {
                    item.Status = "Yazıldı / Written";
                    item.Time = DateTime.Now.ToString("HH:mm:ss");
                    MarkBatchLine(item.LineIndex, $"# OK {item.CardNumber}  UID={uid}");
                    AppendLog($"[BATCH] {item.CardNumber} (UID {uid}) - BAŞARILI / SUCCESS");
                    done++;
                }
                else
                {
                    item.Status = "HATA / ERROR";
                    item.Time = DateTime.Now.ToString("HH:mm:ss");
                    MarkBatchLine(item.LineIndex, $"{item.CardNumber}  # HATA / ERROR (UID={uid}): {OneLine(error)}");
                    AppendLog($"[BATCH] {item.CardNumber} (UID {uid}) - HATA / ERROR: {error}");
                    SetStatus($"[{i + 1}/{_batchItems.Count}] HATA / ERROR: {item.CardNumber} - {error}", StatusKind.Error);
                    failed++;
                }
            }

            if (!_closing)
            {
                var kind = failed == 0 ? StatusKind.Success : StatusKind.Warning;
                SetStatus($"Toplu işlem bitti / Batch done — {done} yazıldı / written, {failed} hata / errors. Hatalı satırlar işaretlendi; aynı dosyayı tekrar içe aktararak yeniden deneyebilirsiniz.", kind);
            }
        }
        finally
        {
            _batchMode = false;
            StartBatchButton.IsEnabled = true;
            ImportBatchButton.IsEnabled = true;
        }
    }

    private static string StripInlineComment(string line)
    {
        var hash = line.IndexOf('#');
        return (hash >= 0 ? line.Substring(0, hash) : line).Trim();
    }

    private static string OneLine(string text)
    {
        return text.Replace("\r", " ").Replace("\n", " ").Trim();
    }

    private void MarkBatchLine(int lineIndex, string newLine)
    {
        if (_batchFilePath is null || lineIndex < 0 || lineIndex >= _batchLines.Count)
        {
            return;
        }

        _batchLines[lineIndex] = newLine;
        try
        {
            File.WriteAllLines(_batchFilePath, _batchLines, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
        catch (Exception ex)
        {
            AppendLog("Liste dosyası güncellenemedi / could not update list file: " + ex.Message);
        }
    }

    private async Task<string?> ReadCurrentUidAsync()
    {
        string? line = null;
        try
        {
            line = await Task.Run(() => _serial.Send("{\"cmd\":\"status\"}", 3));
        }
        catch
        {
        }

        if (line is null)
        {
            if (!_serial.IsConnected)
            {
                await EnsureConnectedAsync(force: true);
            }

            return null;
        }

        var status = JsonLine.Parse(line);
        if (!JsonLine.GetBool(status, "card"))
        {
            return null;
        }

        var uid = JsonLine.GetString(status, "uid") ?? string.Empty;
        return uid.Length > 0 ? uid : null;
    }

    private async Task<string?> WaitForDifferentCardAsync(string? lastUid, int index, int total, string value)
    {
        if (lastUid is not null)
        {
            SetStatus($"[{index}/{total}] Kartı çıkarıp sıradaki kartı okutun / Remove card, tap the next one", StatusKind.Warning);
            await Task.Delay(1500);
        }

        var removed = lastUid is null;
        var fails = 0;
        while (!_closing)
        {
            string? line = null;
            try
            {
                line = await Task.Run(() => _serial.Send("{\"cmd\":\"status\"}", 3));
            }
            catch
            {
            }

            if (line is null)
            {
                fails++;
                if (!_serial.IsConnected)
                {
                    SetStatus($"[{index}/{total}] Bağlantı/port koptu, yeniden deneniyor / connection lost, retrying...", StatusKind.Warning);
                    await EnsureConnectedAsync(force: true);
                }

                if (fails >= 8)
                {
                    SetStatus("Port/bağlantı yok — toplu işlem durduruldu / port lost, batch stopped", StatusKind.Error);
                    return null;
                }

                await Task.Delay(600);
                continue;
            }

            fails = 0;
            var status = JsonLine.Parse(line);
            var present = JsonLine.GetBool(status, "card");
            var uid = JsonLine.GetString(status, "uid") ?? string.Empty;

            if (!present)
            {
                removed = true;
                SetStatus($"[{index}/{total}] {value} — kart bekleniyor / waiting for card...", StatusKind.Warning);
            }
            else if (uid.Length > 0 && !string.Equals(uid, lastUid, StringComparison.OrdinalIgnoreCase))
            {
                return uid;
            }
            else if (!removed)
            {
                SetStatus($"[{index}/{total}] Önce kartı çıkarın / Remove the card first", StatusKind.Warning);
            }
            else
            {
                SetStatus($"[{index}/{total}] Aynı kart — BAŞKA KART OKUTUNUZ / Tap a DIFFERENT card", StatusKind.Warning);
            }

            await Task.Delay(600);
        }

        return null;
    }

    private void RefreshProfileCombo(string? selectName)
    {
        if (_profileStore is null)
        {
            return;
        }

        var previousName = selectName ?? (ProfileCombo.SelectedItem as CardProfile)?.Name;
        var profiles = _profileStore.Profiles;

        ProfileCombo.ItemsSource = null;
        ProfileCombo.ItemsSource = profiles;

        if (profiles.Count == 0)
        {
            ProfileCombo.SelectedIndex = -1;
            return;
        }

        var index = 0;
        if (!string.IsNullOrWhiteSpace(previousName))
        {
            for (var i = 0; i < profiles.Count; i++)
            {
                if (string.Equals(profiles[i].Name, previousName, StringComparison.OrdinalIgnoreCase))
                {
                    index = i;
                    break;
                }
            }
        }

        ProfileCombo.SelectedIndex = index;
    }

    private enum StatusKind
    {
        Neutral,
        Success,
        Warning,
        Error
    }

    private void SetStatus(string message, StatusKind kind)
    {
        StatusText.Text = message;

        var prefix = kind switch
        {
            StatusKind.Success => "StatusSuccess",
            StatusKind.Warning => "StatusWarning",
            StatusKind.Error => "StatusError",
            _ => "StatusNeutral"
        };

        if (TryFindResource(prefix + "Bg") is Brush background)
        {
            StatusBanner.Background = background;
        }

        if (TryFindResource(prefix + "Border") is Brush border)
        {
            StatusBanner.BorderBrush = border;
        }

        if (TryFindResource(prefix + "Text") is Brush text)
        {
            StatusText.Foreground = text;
        }

        if (TryFindResource(prefix + "Dot") is Brush dot)
        {
            StatusDot.Fill = dot;
        }
    }

    private void OnSerialMessage(string message)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(() => AppendLog(message)));
            return;
        }

        AppendLog(message);
    }

    private void AppendLog(string message)
    {
        if (_closing)
        {
            return;
        }

        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(() => AppendLog(message)));
            return;
        }

        LogBox.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + message + Environment.NewLine);

        if (LogBox.Text.Length > 500_000)
        {
            LogBox.Text = LogBox.Text[^300_000..];
        }

        LogBox.ScrollToEnd();
    }

    private Brush Res(string key) => (Brush)FindResource(key);

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left)
        {
            return;
        }

        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }

        if (WindowState == WindowState.Maximized)
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

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void MaximizeButton_Click(object sender, RoutedEventArgs e)
    {
        ToggleMaximize();
    }

    private void ToggleMaximize()
    {
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);

        if (MaximizeButton is null)
        {
            return;
        }

        var maximized = WindowState == WindowState.Maximized;
        MaximizeButton.Content = maximized ? "\uE923" : "\uE922";
        MaximizeButton.ToolTip = maximized ? "Geri Yükle" : "Büyüt";
    }
}
