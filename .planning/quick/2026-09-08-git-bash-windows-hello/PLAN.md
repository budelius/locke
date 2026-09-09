# Git Bash Windows Hello timeout

## Problem

An interactive `locke keystore set` launched from Git Bash on Windows is
classified as Windows-console interactive. WinRT reports Windows Hello as
available, but its consent dialog cannot complete in this MSYS/mintty host. The
write waits 120 seconds and raises `BiometricDeniedError`; no credential is
stored.

## Plan

1. Treat known MSYS/Git Bash terminal hosts as unable to present the native
   Windows Hello consent UI, just like the existing no-console/non-TTY path.
2. Keep Windows Hello enabled for PowerShell, cmd, Windows Terminal, and other
   native interactive hosts.
3. Emit the existing warning when the prompt is skipped so the OS user session
   boundary is explicit.
4. Add unit tests for MSYS detection and update Windows biometric documentation.
5. Run the focused Python tests, the Python suite, and Ruff.

## Safety

- Do not log, inspect, or move any credential value.
- Do not globally disable biometrics or persist `LOCKE_USE_BIOMETRIC=false`.
- Do not fall through to an unrelated credential backend.
- A failed Windows Hello operation remains fail-closed; only a terminal known
  up front to be unable to host the dialog uses the existing OS-session path.
