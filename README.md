# DeskPilot

DeskPilot is a local desktop AI assistant based on the attached architecture PDF. It accepts natural-language text commands, turns them into structured plans, applies a deterministic permission policy, executes approved PC tools, supports optional LLM planning, and records an SQLite audit log.

## Current working features

- Desktop GUI built with Python Tkinter
- Text command interface
- Local rule-based parser that works without an API key
- Optional OpenAI-compatible structured planning through `OPENAI_API_KEY`
- Optional fully offline structured planning through a local Ollama model
- Approved-directory filesystem controls
- File listing, search, text reading, folder creation, moving, writing, and deletion controls
- Process listing, starting, and stopping
- URL/application opening
- System-status reporting
- Window listing, focusing, and closing when `xdotool`/`wmctrl` are available
- Audio mute, unmute, and volume control when `pactl` is available
- Screen lock, sleep, reboot, and shutdown with confirmation prompts
- Screenshot capture when a supported screenshot utility is available
- Confirmation prompts for risky operations
- Task cancellation flag
- SQLite conversation and audit history
- Optional push-to-talk voice adapter

## Run

```bash
cd /home/ubuntu/deskpilot
python3 run.py
```

Text examples:

```text
help
system status
list my downloads
find report in Downloads
create folder ProjectNotes
open https://example.com
run command python3 --version
```

## Optional LLM planning

The application works in local safe-parser mode without an API key. To use structured LLM planning, set an OpenAI-compatible key and optional model/base URL:

```bash
export OPENAI_API_KEY="your-key"
export OPENAI_API_BASE="https://api.openai.com/v1"
export DESKPILOT_MODEL="gpt-4o-mini"
python3 run.py
```

Do not place credentials in the source code or in the assistant's memory.

## Offline operation

DeskPilot has three modes:

1. **Offline safe-parser mode**: works immediately without network access or a model. It supports the built-in commands documented below.
2. **Offline local-model mode**: install [Ollama](https://ollama.com), download a model, and DeskPilot will use it before any cloud provider:

   ```bash
   ollama pull llama3.2:3b
   export DESKPILOT_LOCAL_MODEL=llama3.2:3b
   python3 run.py
   ```

3. **Cloud model mode**: used only when a local Ollama model is unavailable and `OPENAI_API_KEY` is configured.

To prevent all cloud fallback, set:

```bash
export DESKPILOT_OFFLINE_ONLY=1
python3 run.py
```

In offline-only mode, no request is sent to a cloud model. The application can still perform the deterministic built-in commands.

Additional commands include:

```text
list windows
focus window Terminal
close window Calculator
mute sound
unmute audio
set volume to 40%
lock computer
take a screenshot
sleep computer
restart computer
shutdown computer
```

The OS must provide the relevant command-line integration. Missing utilities produce a clear error rather than silently failing.

## Optional voice input

Install the optional dependencies from `requirements-voice.txt`, then use the **Voice** button:

```bash
python3 -m pip install -r requirements-voice.txt
```

The voice feature is push-to-talk and uses the same command planner and safety controls as typed input. If no microphone backend is available, the app remains fully usable in text mode.

## Safety model

- Only approved directories are accessible.
- Read-only actions are automatic.
- File changes, process control, and commands require approval.
- Destructive actions are not enabled silently.
- The assistant does not execute arbitrary model output directly.
- Every tool call and policy decision is written to `data/deskpilot.db`.
- The Cancel button sets a cancellation event for the active task.

## Project structure

```text
deskpilot/
├── deskpilot/app.py       # desktop UI, planner, policy engine, tools
├── deskpilot/voice.py     # optional push-to-talk adapter
├── tests/test_core.py     # policy and parser tests
├── data/                  # local SQLite audit database
├── run.py                 # launcher
└── requirements-voice.txt
```

This is a safe, runnable first release. Cloud email, calendar, browser form automation, visual mouse control, and full cross-platform window-management adapters should be added as separate typed connectors rather than unrestricted shell or mouse automation.
