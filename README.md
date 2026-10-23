# PN5180 ESP8266 DESFire Manager

> ESP8266 + PN5180 firmware and a Windows (WPF) app to personalize MIFARE DESFire **EV2 / EV3** cards — create applications and files, write data, change keys (including the PICC master key and per-card key diversification), and read cards back.

![platform](https://img.shields.io/badge/firmware-ESP8266-blue)
![reader](https://img.shields.io/badge/reader-PN5180-informational)
![card](https://img.shields.io/badge/card-DESFire%20EV2%2FEV3-success)
![app](https://img.shields.io/badge/app-WPF%20.NET%208-512BD4)
![license](https://img.shields.io/badge/license-MIT-green)

---

## Overview

A cheap **NodeMCU v3 (ESP8266)** + **PN5180** turned into a scriptable DESFire card personalization station. The firmware hides all DESFire secure-messaging complexity (AES / 3DES session keys, CMAC, enciphered communication, ChangeKey cryptograms) behind a simple **line-delimited JSON protocol over USB serial**. A Windows **WPF** app drives that protocol so non-technical staff can issue cards from predefined profiles.

## Features

- **Full DESFire workflow** — format, create application, create files, write/read data, change keys, delete, memory/key/version queries.
- **AES, 2K3DES/ISO and legacy DES** authentication with correct EV1 secure messaging (running IV, CMAC, enciphered `CommMode`).
- **Enciphered (CommMode = Full) files** — required by readers like Suprema; both write and read-back supported.
- **ChangeKey** done right — same/cross-key cryptograms, AES key-version byte, and **PICC master key change including a DES ↔ AES type change**.
- **Key diversification (AN10922-style, AES-CMAC)** — a unique key per card derived from `UID + AID`; the master key never leaves the PC and is never written to the card. The reader (read) key is kept fixed.
- **WPF manager app** — profile-based preparation, batch mode, card read-back, standalone format, bilingual (TR/EN) UI.
- **Key protection at rest** — profile keys are encrypted with **Windows DPAPI** (per user + per machine) and shown masked (`****`) in the UI.
- **Guardrails** — confirmation prompts before destructive/irreversible actions (format, PICC master change).

## Repository layout

```
.
├─ firmware/
│   └─ pn5180_desfire_firmware/        # Arduino sketch (ESP8266) + vendored PN5180 library (src/)
├─ host-wpf/
│   └─ DesfireManager/                 # Windows WPF app (.NET 8)
├─ README.md
└─ LICENSE
```

## Hardware

| PN5180 pin | NodeMCU v3 (ESP8266) | GPIO |
|------------|----------------------|------|
| NSS / CS   | D8                   | 15   |
| BUSY       | D1                   | 5    |
| RST        | D2                   | 4    |
| SCK        | D5                   | 14   |
| MOSI       | D7                   | 13   |
| MISO       | D6                   | 12   |
| 3V3        | 3V3                  | —    |
| 5V         | VIN (5V)             | —    |
| GND        | GND                  | —    |

The PN5180 needs a solid **5V** supply for the RF field (logic is 3.3V, level-safe for the ESP8266). IRQ is not required — the firmware polls BUSY with bounded timeouts.

## Getting started

### 1. Flash the firmware
1. Open `firmware/pn5180_desfire_firmware/pn5180_desfire_firmware.ino` in the Arduino IDE.
2. Install ESP8266 board support and select your NodeMCU v3 board.
3. The PN5180 library is **vendored** inside the sketch (`src/pn5180lib`, a patched copy with bounded waits) — no global install needed.
4. Wire the reader as above, flash, open the serial monitor at **115200 8N1**. On boot you should see:
   ```json
   {"event":"boot","fw":"1.0.0","proto":1}
   ```

### 2. Build and run the WPF app
1. Open `host-wpf/DesfireManager/DesfireManager.csproj` in Visual Studio 2022 (or `dotnet build`). Target framework: **.NET 8 (Windows)**.
2. Run it; the app auto-detects the serial port. Create a profile, place a blank card, enter the data and prepare it. **Read** reads a card back; **Format** erases one.

## WPF manager app

- **Profiles** — create, edit, **rename** and delete card configuration profiles.
- **Diversification & PICC** — enable AN10922 key diversification and change the PICC master key (fixed or per-card diversified; DES ↔ AES type change).
- **Key protection** — all key fields are masked (`****`) and stored encrypted with Windows **DPAPI** (per user + per machine). The encrypted profile file cannot be decrypted on another computer or account.
- **Guardrails** — confirmation prompts before irreversible actions (format, PICC master change); an **Info** window (TR/EN) with security notes, a disclaimer and key-storage tips.
- **Bilingual** — every label is Turkish + English.

## Batch personalization

Prepare many cards in one run from a plain text list (one value per line; `#` for comments). Use **Download Sample** to get a template.

- Progress is written back into the list file: a done line becomes `# OK <value>  UID=<card uid>`, a failed line becomes `<value>  # HATA / ERROR: <reason>`. Re-importing the same file skips the done lines and **resumes where it left off**.
- **Same-card guard** — after a card is written, the app re-checks the UID right before each write and waits until a **different** card is presented, so the same card is never written twice — even across a connection drop.
- Errors don't halt the run: the failed line is marked and the batch continues. The list file is flushed to disk after every card, so nothing is lost if the app or the port closes.

## Serial protocol

Requests are single-line JSON (`{"cmd":"...", ...}`, ≤ 512 bytes); the device returns exactly one response line and may emit `{"event":...}` notifications.

| Command | Purpose |
|---------|---------|
| `ping` / `status` / `version` | liveness, card/session state, reader version |
| `scan` / `reset` | re-activate card / reset the RF session |
| `auth` | authenticate a key slot (`des` / `iso` / `aes`) |
| `select_app` / `list_apps` | select / list applications |
| `create_app` / `delete_app` / `free_memory` | application management |
| `get_key_settings` / `get_key_version` / `change_key` | key management |
| `get_file_ids` / `get_file_settings` / `create_file` / `delete_file` / `change_file_settings` | file management |
| `read_data` / `write_data` | file I/O (plain and enciphered) |
| `zero_scan` / `dump` | try default keys / dump card contents |
| `format` | erase the card (two-phase, token-confirmed) |

## Security notes

- The RF link (card ↔ reader) is protected by DESFire's own AES/CMAC/enciphered messaging. Keys only ever exist in the clear on the PC and on the USB serial line — treat the station as trusted and keep key material safe.
- The WPF app stores profile keys encrypted with Windows DPAPI (per user + per machine). **The encrypted profile file cannot be decrypted on another computer or user account.** Keep a separate, safe backup of your keys.
- Never commit real keys. The bundled `profiles.json` ships with zeroed placeholder keys only.

> ⚠️ **PICC master key change is irreversible.** If you change a card's PICC master key (or its crypto type) and lose the key — or write a wrong value — the card is **permanently bricked**; DESFire has no recovery. The DES↔AES type-change path is **experimental** — test on a sacrificial card first and verify you can still format it before using it in production.

## Supported cards

Tested against MIFARE DESFire **EV2** and **EV3**.

## Credits

- NFC front-end driver: **[ATrappmann/PN5180-Library](https://github.com/ATrappmann/PN5180-Library)**. A patched copy is vendored under `firmware/pn5180_desfire_firmware/src/pn5180lib` (bounded BUSY/IRQ waits + watchdog feeding) and remains under **its own license** — see the upstream repository; this project's MIT license does not apply to it.
- DESFire secure messaging and key diversification follow the public NXP application notes (AN10922); the CRC32 and AES-CMAC implementations here are written independently from those specifications.

## License

This project's own code is released under the **MIT License** — see [`LICENSE`](LICENSE). Copyright © 2026 Eren Çakıcı. The vendored PN5180 library retains its original license.

## Disclaimer

Provided as-is, with no warranty. The author (Eren Çakıcı) accepts no responsibility and is not liable for any damages, data loss, or bricked cards. Use only on cards you own or are authorized to personalize. You are responsible for key management and for any cards bricked by irreversible operations.
