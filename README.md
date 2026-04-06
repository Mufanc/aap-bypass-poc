# aap-bypass-poc

A proof-of-concept tool that bypasses Android's [Audio Input Sharing](https://developer.android.com/media/platform/sharing-audio-input) restrictions, allowing a designated process to capture audio concurrently with other apps — without being silenced by the system's priority policy.

## Background

Starting from Android 10, the system enforces a strict priority-based policy on audio input access. When multiple apps attempt to capture audio simultaneously, only one (or two in limited cases) will receive actual audio data — lower-priority apps are silently muted. This mechanism prevents concurrent audio recording across apps, which can be limiting for power users running custom audio pipelines or system-level tools.

## What This Tool Does

This tool patches the `audioserver` process at runtime so that audio capture requests from **root processes** are always granted active status, regardless of the system's priority rules. In effect, a root process will never be silenced by other apps competing for the microphone.

- **Scope**: Only root (UID 0) processes are affected. The behavior for all other apps remains completely unchanged.
- **Compatibility**: Supports Android 14 (API 34) and Android 15+ (API 35). Older versions are not supported.

## How It Works

The tool locates a specific policy-decision function inside the running `audioserver` process and applies an inline hook to it. The hook intercepts the app-state evaluation logic and forces the "active" state for clients running as root, effectively exempting them from the normal silencing policy. The patch is applied in-memory and does not modify any files on disk.

## Requirements

- A rooted Android device
- ADB access
- Android NDK (for cross-compilation)

## Building

```sh
just run
```
