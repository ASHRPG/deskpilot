# DeskPilot

DeskPilot is a local desktop AI assistant based on the architecture specification. It accepts natural-language text and voice commands, turns them into structured plans, applies a deterministic permission policy, executes approved PC tools, speaks responses, and records an SQLite audit log.

## Features

- Tkinter desktop GUI when a graphical display is available
- Automatic terminal mode for GitHub Codespaces, SSH, CI, and servers without `DISPLAY`
- Text commands and push-to-talk voice commands
- Local spoken replies through `pyttsx3` or `espeak`
- Local rule-based parser that works without an API key
- Optional OpenAI-compatible structured planning
- Optional fully offline structured planning through a local Ollama model
- Optional offline speech recognition through Vosk or faster-whisper
- Approved-directory filesystem controls
- File listing, search, reading, folder creation, moving, writing, and deletion controls
- Process listing, starting, and stopping
- URL/application opening
- Window listing, focusing, and closing when `xdotool`/`wmctrl` are available
- Audio mute, unmute, and volume control when `pactl` is available
- Screen lock, sleep, reboot, and shutdown with confirmation prompts
- Screenshot capture when a supported utility is available
- Task cancellation and SQLite conversation/audit history

## Run locally

```bash
cd /home/ubuntu/deskpilot
python3 run.py
```

The desktop window requires a graphical session with `DISPLAY` or `WAYLAND_DISPLAY`.

## Run in GitHub Codespaces or SSH

If no graphical display is available, DeskPilot automatically starts a terminal interface instead of crashing with `TclError: no display name`:

```text
DeskPilot terminal mode (no graphical DISPLAY detected). Type 'help' or 'exit'.
deskpilot> system status
```

You can force terminal mode anywhere:

```bash
DESKPILOT_HEADLESS=1 python3 run.py
```

Risky actions continue to require an interactive `y/N` confirmation in terminal mode.

## Example commands

```text
help
system status
list my downloads
find report in Downloads
create folder ProjectNotes
open https://example.com
list windows
focus window Terminal
close window Calculator
mute sound
set volume to 40%
lock computer
take a screenshot
run command python3 --version
```

## Offline operation

DeskPilot has three layers of offline capability:

1. **Offline safe-parser mode** works immediately without a network connection or AI model.
2. **Offline local-model mode** provides broad natural-language planning with Ollama:

   ```bash
   ollama pull llama3.2:3b
   export DESKPILOT_LOCAL_MODEL=llama3.2:3b
   export DESKPILOT_OFFLINE_ONLY=1
   python3 run.py
   ```

3. **Offline voice mode** uses a local speech-recognition backend. The assistant always speaks replies locally when a TTS backend is installed.

To prevent every cloud fallback, use `DESKPILOT_OFFLINE_ONLY=1`.

## Voice setup

Install microphone capture and local speech output:

```bash
python3 -m pip install -r requirements-voice.txt
```

For Linux, you may also need:

```bash
sudo apt install portaudio19-dev python3-pyaudio espeak
```

Click **Listen**, speak a command, and DeskPilot sends the transcript through the same planner and safety policy used for typed commands. **Speak replies** is enabled by default.

For fully offline speech recognition, choose one backend:

```bash
# Vosk: lightweight offline recognition; download a Vosk model separately
python3 -m pip install -r requirements-offline-voice.txt
export DESKPILOT_VOSK_MODEL=/path/to/vosk-model

# Or faster-whisper: higher accuracy and more CPU/RAM usage
pip install faster-whisper
export DESKPILOT_WHISPER_MODEL=small.en
```

If no offline speech variable is configured, the optional SpeechRecognition online fallback is used for transcription. Spoken responses remain local.

## Broad natural-language commands

With an Ollama model, DeskPilot can interpret many differently worded requests and combine multiple registered tools in one plan. New computer capabilities should be added as typed tools with schemas and risk levels. The model never receives unrestricted execution authority, and arbitrary model-generated shell commands are not run automatically.

## Safety model

- Only approved directories are accessible.
- Read-only actions are automatic.
- File changes, process control, and commands require approval.
- Destructive and power actions are never enabled silently.
- Every tool call and policy decision is written to `data/deskpilot.db`.
- The Cancel button or terminal interruption stops the active task as soon as possible.
- External documents are treated as untrusted data rather than instructions.

## Project structure

```text
deskpilot/
├── deskpilot/app.py
├── deskpilot/voice.py
├── tests/test_core.py
├── data/
├── run.py
├── requirements-voice.txt
├── requirements-offline-voice.txt
└── README.md
```
