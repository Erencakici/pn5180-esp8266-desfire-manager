using System.IO;
using System.IO.Ports;
using System.Text;
using System.Text.RegularExpressions;

namespace DesfireManager.Services;

public sealed class SerialLink : IDisposable
{
    private static readonly Regex CommandPattern = new(
        "\"cmd\"\\s*:\\s*\"([a-z_]+)\"",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly object _gate = new();
    private SerialPort? _port;
    private bool _disposed;

    public event Action<string>? MessageLogged;

    public string? PortName { get; private set; }

    public bool IsConnected
    {
        get
        {
            lock (_gate)
            {
                return !_disposed && _port?.IsOpen == true;
            }
        }
    }

    public bool Connect()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return false;
            }

            CloseCore();

            string[] portNames;
            try
            {
                portNames = SerialPort.GetPortNames();
            }
            catch (Exception)
            {
                return false;
            }

            foreach (var name in portNames.OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
            {
                SerialPort? candidate = null;
                try
                {
                    candidate = new SerialPort(name, 115200, Parity.None, 8, StopBits.One)
                    {
                        NewLine = "\n",
                        ReadTimeout = 1400,
                        WriteTimeout = 1000,
                        DtrEnable = false,
                        RtsEnable = false,
                        Handshake = Handshake.None,
                        Encoding = Encoding.ASCII
                    };

                    candidate.Open();
                    Thread.Sleep(400);

                    string? response = null;
                    for (var attempt = 0; attempt < 3 && response is null; attempt++)
                    {
                        try
                        {
                            candidate.DiscardInBuffer();
                        }
                        catch (Exception)
                        {
                        }

                        try
                        {
                            candidate.WriteLine("{\"cmd\":\"ping\"}");
                        }
                        catch (Exception)
                        {
                        }

                        response = ReadFor(candidate, "ping", 2);
                    }

                    if (response is not null)
                    {
                        _port = candidate;
                        PortName = name;
                        return true;
                    }
                }
                catch (Exception)
                {
                }
                finally
                {
                    if (!ReferenceEquals(_port, candidate))
                    {
                        try
                        {
                            candidate?.Close();
                        }
                        catch (Exception)
                        {
                        }

                        try
                        {
                            candidate?.Dispose();
                        }
                        catch (Exception)
                        {
                        }
                    }
                }
            }

            return false;
        }
    }

    public string? Send(string json, int seconds = 6)
    {
        var command = ExtractCommand(json);

        lock (_gate)
        {
            if (_disposed || _port is null || !_port.IsOpen)
            {
                WriteLog("Port kapali");
                return null;
            }

            try
            {
                _port.DiscardInBuffer();
            }
            catch (Exception)
            {
            }

            try
            {
                _port.WriteLine(json);
            }
            catch (Exception)
            {
                WriteLog("yazma hatasi");
                return null;
            }

            var response = ReadFor(_port, command, seconds);
            if (response is not null)
            {
                if (Regex.IsMatch(response, "\"ok\"\\s*:\\s*true", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                {
                    WriteLog($"  {command}  OK");
                }
                else
                {
                    WriteLog($"  {command}  HATA: {response}");
                }
            }
            else
            {
                WriteLog($"  {command}  (yanit yok)");
            }

            return response;
        }
    }

    public bool SendOk(string json, int seconds = 6)
    {
        return JsonLine.IsOk(Send(json, seconds));
    }

    public void WriteLog(string message)
    {
        MessageLogged?.Invoke(message);
    }

    public void Disconnect()
    {
        lock (_gate)
        {
            CloseCore();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            CloseCore();
        }
    }

    private static string? ReadFor(SerialPort port, string expectedCommand, int seconds)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < deadline)
        {
            string? line;
            try
            {
                line = port.ReadLine();
            }
            catch (TimeoutException)
            {
                continue;
            }
            catch (IOException)
            {
                Thread.Sleep(25);
                continue;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
            catch (Exception)
            {
                Thread.Sleep(25);
                continue;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (line.Contains("\"event\"", StringComparison.Ordinal))
            {
                continue;
            }

            if (string.IsNullOrEmpty(expectedCommand)
                || Regex.IsMatch(line, "\"cmd\"\\s*:\\s*\"" + Regex.Escape(expectedCommand) + "\""))
            {
                return line;
            }
        }

        return null;
    }

    private static string ExtractCommand(string json)
    {
        var match = CommandPattern.Match(json);
        return match.Success ? match.Groups[1].Value : string.Empty;
    }

    private void CloseCore()
    {
        if (_port is not null)
        {
            try
            {
                _port.Close();
            }
            catch (Exception)
            {
            }

            try
            {
                _port.Dispose();
            }
            catch (Exception)
            {
            }
        }

        _port = null;
        PortName = null;
    }
}
