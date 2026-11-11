# What the AFKLink app sends from your PC

A short version is in the [README](README.md#privacy). Русская версия: [PRIVACY.ru.md](PRIVACY.ru.md)

## To the AFKLink server

- the PC ID and public key. On every connection the PC signs the server's challenge with its
  key; the private key stays on the PC;
- the app version, build commit and channel, and how the previous run ended;
- a hardware fingerprint: a SHA-256 hash of the Windows MachineGuid, the SMBIOS UUID and the
  system disk's serial number (the values themselves are not sent), and whether the PC looks
  like a virtual machine;
- the PC's name (the Windows computer name until you change it);
- pairing: requests for a pairing code, your answers to access requests, removed access;
- what is needed to set up a connection: the session description and network addresses;
- session statistics: resolution, frame counts, encoding time, bitrate, quality changes, input
  event counts by type (not which keys), the input path and driver state, whether the
  connection was direct or relayed, and why the session ended;
- app events: start, crash, the result of an update or a driver install, a changed PC setting;
- logs when you click “Send logs”: your comment under “What happened?”, the system log, the logs
  of the last five sessions, the update watchdog's and the driver installer's logs, the last
  15 minutes of detailed lines kept in memory, selected `config.json` fields (PC name, settings,
  the game's path with your user folder masked) and a system summary (Windows, displays, CPU,
  memory; no user or computer name, paths or network addresses), up to 24 MiB in total. The log
  files can contain the Telegram IDs of people who connected and the network addresses of
  connections;
- an automatic report after a crash, a long loss of connection, a failed session or a hang: the
  tail of the log, at most the last half hour and 200 KB, at most three a day. Lines that name a
  keyboard key or shortcut are left out and your user folder is masked. With the log level set
  to “Off”, nothing is sent;
- if the app cannot start because the WebView2 Runtime is missing: one report with the PC ID,
  app version, channel and commit, the Windows build and the error code;
- the update check (official builds only).

## Between the PC and your device

Video, input and the clipboard (only when the viewer turns clipboard sync on) go directly
between the PC and the viewer's device, or through the AFKLink TURN relay when there is no
direct path. WebRTC encrypts all of it (DTLS-SRTP for video, DTLS for data channels), and the
relay only forwards encrypted packets. The AFKLink server passes the connection setup between
the two sides and decides who may connect, so it is part of the trust boundary: see
[SECURITY.md](SECURITY.md#trust-model).

## What stays on the PC

The History tab (who connected and when, kept for 90 days, never sent) stays on the PC. The log
files stay there too and leave it only as described above.
