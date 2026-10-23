# Vendored PN5180 library (patched)

Copied from `Documents/Arduino/libraries/PN5180_Library` (upstream: obrazc/PN5180,
LGPL 2.1) and patched for this project. The sketch includes it via
`#include "src/pn5180lib/PN5180.h"`, so the Arduino builder compiles **this**
copy and ignores the global, unpatched one. Keeping it in the sketch makes the
fix reproducible in git and immune to Library Manager updates.

## Why

The upstream code spins forever inside `transceiveCommand()` (5 BUSY waits),
`setRF_on()`, `setRF_off()` and `reset()` (IRQ waits) without feeding the
watchdog. A PN5180 that stalls mid-command (card yanked, RF glitch) then
starves the ESP8266 soft WDT → board reboots mid-operation. This was the
"NodeMCU restarts during any operation" failure.

## Patch summary vs upstream

- `pn5180WaitLevel()` helper: every BUSY/IRQ spin is now **bounded**
  (50 ms for SPI BUSY transitions, 500 ms for RF on/off IRQs, 1 s for the
  post-reset IDLE IRQ) and calls `yield()` (feeds the ESP8266 watchdog).
  On timeout the call returns `false`, deasserting NSS first when needed.
- Real error propagation: `readRegister`, `writeRegister`,
  `writeRegisterWithOrMask/AndMask`, `sendData`, `readData`, `loadRFConfig`
  now return the actual SPI result instead of always `true`/non-null. The
  sketch maps failures to `RF_RET_REGFAIL` / wedge recovery.
- `readRegister()` zeroes the output value before the exchange; `getIRQStatus()`
  initialises its accumulator, so a failed read can't return stack garbage.
- `PN5180ISO14443.cpp` includes `"PN5180.h"` (quote) instead of `<PN5180.h>`
  so this tree is self-contained.

If you update the library upstream, re-apply these changes (compare against the
stock copy in `Documents/Arduino/libraries/PN5180_Library`).
