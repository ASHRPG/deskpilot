from __future__ import annotations

import datetime as dt
import json
import os
import queue
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import uuid
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .voice import backend_info, listen_once, speak

APP_NAME = "DeskPilot"
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "deskpilot.db"
DEFAULT_ALLOWED = [Path.home() / "Documents", Path.home() / "Downloads", Path.home() / "Desktop", BASE_DIR]


@dataclass
class ToolSpec:
    name: str
    description: str
    risk: int
    reversible: bool


@dataclass
class Step:
    tool: str
    arguments: dict[str, Any]
    explanation: str
    risk: int
    requires_confirmation: bool = False
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])


@dataclass
class Plan:
    goal: str
    steps: list[Step]
    response: str = ""
    missing_information: list[str] = field(default_factory=list)


class AuditLog:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, event TEXT, detail TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS conversations (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, role TEXT, content TEXT)")
            self.db.commit()

    def event(self, event: str, detail: Any) -> None:
        with self.lock:
            self.db.execute("INSERT INTO audit(ts,event,detail) VALUES(?,?,?)", (dt.datetime.now().isoformat(timespec="seconds"), event, json.dumps(detail, default=str)))
            self.db.commit()

    def message(self, role: str, content: str) -> None:
        with self.lock:
            self.db.execute("INSERT INTO conversations(ts,role,content) VALUES(?,?,?)", (dt.datetime.now().isoformat(timespec="seconds"), role, content))
            self.db.commit()

    def recent(self, limit: int = 100) -> list[tuple]:
        with self.lock:
            return list(self.db.execute("SELECT ts,event,detail FROM audit ORDER BY id DESC LIMIT ?", (limit,)))


class PolicyEngine:
    RISK_NAMES = {0: "read-only", 1: "reversible", 2: "disruptive", 3: "high impact"}

    def __init__(self, allowed_dirs: list[Path]):
        self.allowed_dirs = [p.expanduser().resolve() for p in allowed_dirs]
        self.enabled: dict[str, bool] = {}

    def path_allowed(self, path: str) -> bool:
        try:
            p = Path(path).expanduser().resolve()
            return any(p == base or base in p.parents for base in self.allowed_dirs)
        except (OSError, RuntimeError):
            return False

    def evaluate(self, step: Step) -> dict[str, Any]:
        args = step.arguments
        if step.tool.startswith("filesystem."):
            path = args.get("path") or args.get("source") or args.get("destination")
            if path and not self.path_allowed(path):
                return {"decision": "deny", "risk": 3, "reason": "Path is outside the approved directories.", "preview": str(path)}
            if step.tool in {"filesystem.delete", "filesystem.write_text", "filesystem.move", "filesystem.copy"}:
                return {"decision": "require_confirmation", "risk": max(step.risk, 2), "reason": "This changes local files.", "preview": step.explanation}
        if step.tool in {"process.start", "process.stop", "app.close"}:
            return {"decision": "require_confirmation", "risk": max(step.risk, 2), "reason": "This changes running processes.", "preview": step.explanation}
        if step.tool.startswith("external."):
            return {"decision": "require_confirmation", "risk": 3, "reason": "This affects an external service.", "preview": step.explanation}
        if step.requires_confirmation or step.risk >= 2:
            return {"decision": "require_confirmation", "risk": step.risk, "reason": "This action may be disruptive.", "preview": step.explanation}
        return {"decision": "allow", "risk": step.risk, "reason": "Low-risk action.", "preview": step.explanation}


class Tools:
    def __init__(self, policy: PolicyEngine, audit: AuditLog, cancel: threading.Event):
        self.policy = policy
        self.audit = audit
        self.cancel = cancel
        self.children: dict[str, subprocess.Popen] = {}

    def run(self, step: Step) -> str:
        if self.cancel.is_set():
            raise RuntimeError("Task cancelled")
        fn = getattr(self, "_" + step.tool.replace(".", "_"), None)
        if not fn:
            raise ValueError(f"Unsupported tool: {step.tool}")
        self.audit.event("tool_started", {"tool": step.tool, "arguments": step.arguments})
        result = fn(**step.arguments)
        self.audit.event("tool_completed", {"tool": step.tool, "result": result})
        return result

    def _filesystem_list(self, path: str) -> str:
        p = Path(path).expanduser()
        if not self.policy.path_allowed(str(p)):
            raise PermissionError("Directory is not approved")
        if not p.exists():
            return f"Directory does not exist: {p}"
        entries = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))[:200]
        return "\n".join(("[DIR] " if e.is_dir() else "      ") + e.name for e in entries) or "Directory is empty."

    def _filesystem_search(self, path: str, query: str) -> str:
        root = Path(path).expanduser()
        if not self.policy.path_allowed(str(root)):
            raise PermissionError("Directory is not approved")
        matches = []
        for p in root.rglob("*"):
            if self.cancel.is_set():
                raise RuntimeError("Task cancelled")
            if query.lower() in p.name.lower():
                matches.append(str(p))
            if len(matches) >= 100:
                break
        return "\n".join(matches) or "No matching files found."

    def _filesystem_read_text(self, path: str) -> str:
        p = Path(path).expanduser()
        if not self.policy.path_allowed(str(p)):
            raise PermissionError("File is outside approved directories")
        if p.stat().st_size > 2_000_000:
            raise ValueError("File is larger than the safe preview limit")
        return p.read_text(errors="replace")[:10000]

    def _filesystem_create_folder(self, path: str) -> str:
        p = Path(path).expanduser()
        if not self.policy.path_allowed(str(p)):
            raise PermissionError("Directory is not approved")
        p.mkdir(parents=True, exist_ok=True)
        return f"Created folder: {p}"

    def _filesystem_write_text(self, path: str, content: str) -> str:
        p = Path(path).expanduser()
        if not self.policy.path_allowed(str(p)):
            raise PermissionError("File is outside approved directories")
        p.write_text(content)
        return f"Wrote {len(content)} characters to {p}"

    def _filesystem_move(self, source: str, destination: str) -> str:
        if not self.policy.path_allowed(source) or not self.policy.path_allowed(destination):
            raise PermissionError("Source and destination must be approved")
        src, dst = Path(source).expanduser(), Path(destination).expanduser()
        shutil.move(str(src), str(dst))
        return f"Moved {src} to {dst}"

    def _filesystem_delete(self, path: str) -> str:
        p = Path(path).expanduser()
        if not self.policy.path_allowed(str(p)):
            raise PermissionError("File is outside approved directories")
        if p.is_dir():
            raise ValueError("Directory deletion is disabled in this version")
        p.unlink()
        return f"Deleted {p}"

    def _process_list(self) -> str:
        try:
            result = subprocess.run(["ps", "-eo", "pid,comm,%cpu,%mem"], capture_output=True, text=True, timeout=5)
            return result.stdout[:10000]
        except Exception as e:
            return f"Unable to list processes: {e}"

    def _process_start(self, command: str, cwd: str | None = None) -> str:
        parts = shlex.split(command)
        if not parts:
            raise ValueError("Command is empty")
        executable = shutil.which(parts[0])
        if not executable:
            raise FileNotFoundError(f"Executable not found: {parts[0]}")
        workdir = str(Path(cwd).expanduser()) if cwd else str(Path.home())
        if cwd and not self.policy.path_allowed(workdir):
            raise PermissionError("Working directory is not approved")
        proc = subprocess.Popen(parts, cwd=workdir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.children[str(proc.pid)] = proc
        return f"Started process PID {proc.pid}: {command}"

    def _process_stop(self, pid: int) -> str:
        proc = self.children.get(str(pid))
        if proc:
            proc.terminate()
            return f"Stopped managed process {pid}"
        os.kill(int(pid), 15)
        return f"Sent termination signal to process {pid}"

    def _app_open(self, target: str) -> str:
        if re.match(r"^https?://", target):
            webbrowser.open(target)
            return f"Opened URL: {target}"
        p = Path(target).expanduser()
        if p.exists() and not self.policy.path_allowed(str(p)):
            raise PermissionError("Application target is outside approved locations")
        if shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", str(p if p.exists() else target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            raise RuntimeError("xdg-open is not available")
        return f"Opened: {target}"

    def _app_close(self, target: str) -> str:
        if not shutil.which("xdotool"):
            raise RuntimeError("xdotool is required for window control")
        ids = subprocess.check_output(["xdotool", "search", "--name", target], text=True, stderr=subprocess.DEVNULL).split()
        if not ids:
            return f"No window matched: {target}"
        for wid in ids[:5]:
            subprocess.run(["xdotool", "windowclose", wid], check=False)
        return f"Closed {len(ids[:5])} window(s) matching {target}"

    def _window_list(self) -> str:
        if shutil.which("wmctrl"):
            return subprocess.check_output(["wmctrl", "-l"], text=True, stderr=subprocess.DEVNULL)[:10000] or "No windows reported."
        if shutil.which("xdotool"):
            ids = subprocess.check_output(["xdotool", "search", "--name", "."], text=True, stderr=subprocess.DEVNULL).split()
            names = []
            for wid in ids[:100]:
                try:
                    names.append(f"{wid}: {subprocess.check_output(['xdotool', 'getwindowname', wid], text=True, stderr=subprocess.DEVNULL).strip()}")
                except Exception:
                    pass
            return "\n".join(names) or "No windows reported."
        raise RuntimeError("Install wmctrl or xdotool for window listing")

    def _window_focus(self, title: str) -> str:
        if not shutil.which("xdotool"):
            raise RuntimeError("xdotool is required for window control")
        ids = subprocess.check_output(["xdotool", "search", "--name", title], text=True, stderr=subprocess.DEVNULL).split()
        if not ids:
            return f"No window matched: {title}"
        subprocess.run(["xdotool", "windowactivate", ids[0]], check=False)
        return f"Focused window matching {title}"

    def _system_mute(self, muted: bool = True) -> str:
        if not shutil.which("pactl"):
            raise RuntimeError("pactl is required for audio control")
        subprocess.run(["pactl", "set-sink-mute", "@DEFAULT_SINK@", "1" if muted else "0"], check=True)
        return "Audio muted" if muted else "Audio unmuted"

    def _system_volume(self, percent: int) -> str:
        if not shutil.which("pactl"):
            raise RuntimeError("pactl is required for audio control")
        percent = max(0, min(150, int(percent)))
        subprocess.run(["pactl", "set-sink-volume", "@DEFAULT_SINK@", f"{percent}%"], check=True)
        return f"Audio volume set to {percent}%"

    def _system_lock(self) -> str:
        if shutil.which("loginctl"):
            subprocess.run(["loginctl", "lock-session"], check=False)
        elif shutil.which("xdg-screensaver"):
            subprocess.run(["xdg-screensaver", "lock"], check=False)
        else:
            raise RuntimeError("No supported screen-lock command is available")
        return "Screen lock requested"

    def _system_sleep(self) -> str:
        if not shutil.which("systemctl"):
            raise RuntimeError("systemctl is required for sleep")
        subprocess.run(["systemctl", "suspend"], check=False)
        return "Sleep requested"

    def _system_shutdown(self, reboot: bool = False) -> str:
        if not shutil.which("systemctl"):
            raise RuntimeError("systemctl is required for power control")
        action = "reboot" if reboot else "poweroff"
        subprocess.run(["systemctl", action], check=False)
        return f"System {action} requested"

    def _system_screenshot(self, path: str) -> str:
        p = Path(path).expanduser()
        if not self.policy.path_allowed(str(p)):
            raise PermissionError("Screenshot path is outside approved directories")
        command = None
        if shutil.which("gnome-screenshot"):
            command = ["gnome-screenshot", "-f", str(p)]
        elif shutil.which("scrot"):
            command = ["scrot", str(p)]
        else:
            raise RuntimeError("Install gnome-screenshot or scrot for screenshots")
        subprocess.run(command, check=True)
        return f"Screenshot saved to {p}"

    def _system_status(self) -> str:
        return f"Platform: {os.name}\nHome: {Path.home()}\nTime: {dt.datetime.now().astimezone().isoformat(timespec='seconds')}\nPython: {os.sys.version.split()[0]}"


class LLMClient:
    def __init__(self):
        self.key = os.getenv("OPENAI_API_KEY")
        self.base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1").rstrip("/")
        self.model = os.getenv("DESKPILOT_MODEL", "gpt-4o-mini")
        self.local_base = os.getenv("DESKPILOT_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
        self.local_model = os.getenv("DESKPILOT_LOCAL_MODEL", "llama3.2:3b")
        self.offline_only = os.getenv("DESKPILOT_OFFLINE_ONLY", "0").lower() in {"1", "true", "yes", "on"}

    def available(self) -> bool:
        return bool(self.key) or self.local_available()

    def local_available(self) -> bool:
        try:
            with urllib.request.urlopen(self.local_base + "/api/tags", timeout=0.4) as resp:
                data = json.loads(resp.read())
            models = [m.get("name", "") for m in data.get("models", [])]
            return any(self.local_model == m or self.local_model.split(":")[0] == m.split(":")[0] for m in models)
        except Exception:
            return False

    def plan(self, text: str, tools: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        schema = {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["answer", "plan", "clarify"]},
                "response": {"type": "string"},
                "question": {"type": "string"},
                "goal": {"type": "string"},
                "steps": {"type": "array", "items": {"type": "object", "properties": {"tool": {"type": "string"}, "arguments": {"type": "object"}, "explanation": {"type": "string"}, "risk": {"type": "integer"}}, "required": ["tool", "arguments", "explanation", "risk"]}}
            },
            "required": ["type"]
        }
        system = "You are DeskPilot. Return only JSON matching the schema. Never invent tools. Use low risk for read-only actions. Do not use shell tools; use process.start only for explicit commands."
        payload = {"model": self.model, "temperature": 0, "messages": [{"role": "system", "content": system + "\nAvailable tools:\n" + json.dumps(tools)}, {"role": "user", "content": text}], "response_format": {"type": "json_schema", "json_schema": {"name": "deskpilot_plan", "strict": True, "schema": schema}}}
        local_payload = {"model": self.local_model, "stream": False, "format": "json", "options": {"temperature": 0}, "messages": [{"role": "system", "content": system + "\nReturn JSON with type, response, goal, and steps.\nAvailable tools:\n" + json.dumps(tools)}, {"role": "user", "content": text}]}
        if self.local_available():
            try:
                req = urllib.request.Request(self.local_base + "/api/chat", data=json.dumps(local_payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=90) as resp:
                    data = json.loads(resp.read())
                return json.loads(data["message"]["content"])
            except Exception:
                pass
        if self.offline_only or not self.key:
            return None
        payload["model"] = self.model
        req = urllib.request.Request(self.base + "/chat/completions", data=json.dumps(payload).encode(), headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read())
            return json.loads(data["choices"][0]["message"]["content"])
        except Exception:
            return None


class Planner:
    def __init__(self, tools: Tools, llm: LLMClient):
        self.tools = tools
        self.llm = llm

    def make_plan(self, text: str) -> Plan:
        text = text.strip()
        tool_catalog = [{"name": n.name, "description": n.description, "risk": n.risk} for n in TOOL_CATALOG]
        data = self.llm.plan(text, tool_catalog)
        if data:
            if data.get("type") == "answer":
                return Plan(text, [], response=data.get("response", ""))
            if data.get("type") == "clarify":
                return Plan(text, [], response=data.get("question", ""), missing_information=[data.get("question", "")])
            steps = [Step(s["tool"], s.get("arguments", {}), s.get("explanation", s["tool"]), int(s.get("risk", 1)), int(s.get("risk", 1)) >= 2) for s in data.get("steps", [])]
            return Plan(data.get("goal", text), steps, data.get("response", ""))
        return self.rule_plan(text)

    def rule_plan(self, text: str) -> Plan:
        t = text.lower().strip()
        if t in {"help", "what can you do", "commands"}:
            return Plan(text, [], response="I can list/search/read approved files, create folders, open apps or URLs, list/start/stop processes, report system status, and record every action. Try: 'list my downloads' or 'open https://example.com'.")
        if "system status" in t or "computer status" in t or "pc status" in t:
            return Plan(text, [Step("system.status", {}, "Report local system status", 0)])
        if "list windows" in t or "what windows" in t or "open windows" in t:
            return Plan(text, [Step("window.list", {}, "List open desktop windows", 0)])
        m = re.search(r"(?:focus|switch to|activate) (?:the )?window (?:called |named )?(.+)$", text, re.I)
        if m:
            title = m.group(1).strip().strip('"')
            return Plan(text, [Step("window.focus", {"title": title}, f"Focus window matching {title}", 1)])
        m = re.search(r"(?:close|quit) (?:the )?window (?:called |named )?(.+)$", text, re.I)
        if m:
            title = m.group(1).strip().strip('"')
            return Plan(text, [Step("app.close", {"target": title}, f"Close window matching {title}", 2, True)])
        if "mute" in t and ("sound" in t or "audio" in t or "volume" in t):
            return Plan(text, [Step("system.mute", {"muted": True}, "Mute system audio", 1)])
        if ("unmute" in t or "turn sound on" in t) and ("sound" in t or "audio" in t or "volume" in t):
            return Plan(text, [Step("system.mute", {"muted": False}, "Unmute system audio", 1)])
        m = re.search(r"(?:set|change) (?:the )?(?:system )?volume to (\d{1,3})%?", text, re.I)
        if m:
            percent = int(m.group(1))
            return Plan(text, [Step("system.volume", {"percent": percent}, f"Set system volume to {percent}%", 1)])
        if "lock" in t and ("screen" in t or "computer" in t or "pc" in t):
            return Plan(text, [Step("system.lock", {}, "Lock the screen", 2, True)])
        if "sleep" in t or "suspend" in t:
            return Plan(text, [Step("system.sleep", {}, "Put the computer to sleep", 3, True)])
        if "shutdown" in t or "shut down" in t:
            return Plan(text, [Step("system.shutdown", {"reboot": False}, "Shut down the computer", 3, True)])
        if "restart" in t or "reboot" in t:
            return Plan(text, [Step("system.shutdown", {"reboot": True}, "Restart the computer", 3, True)])
        if "screenshot" in t or "screen shot" in t:
            path = str(Path.home() / "Pictures" / f"deskpilot-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.png")
            return Plan(text, [Step("system.screenshot", {"path": path}, f"Capture screenshot to {path}", 1)])
        if "list" in t and ("download" in t or "files" in t or "folder" in t):
            path = str(Path.home() / "Downloads") if "download" in t else str(Path.home() / "Documents")
            return Plan(text, [Step("filesystem.list", {"path": path}, f"List files in {path}", 0)])
        m = re.search(r"(?:find|search for|look for) (.+?)(?: in (.+))?$", text, re.I)
        if m:
            query = m.group(1).strip().strip('"')
            path = m.group(2) or str(Path.home() / "Downloads")
            return Plan(text, [Step("filesystem.search", {"path": path, "query": query}, f"Search for '{query}' under {path}", 0)])
        m = re.search(r"(?:read|open and read|show me) (.+)$", text, re.I)
        if m and Path(m.group(1).strip()).expanduser().exists():
            path = m.group(1).strip()
            return Plan(text, [Step("filesystem.read_text", {"path": path}, f"Read text from {path}", 0)])
        m = re.search(r"create (?:a )?(?:folder|directory) (?:called|named)?\s*(.+)$", text, re.I)
        if m:
            name = m.group(1).strip().strip('"')
            path = str(Path.home() / "Documents" / name)
            return Plan(text, [Step("filesystem.create_folder", {"path": path}, f"Create folder {path}", 1)])
        m = re.search(r"(?:open|launch|start) (https?://\S+)$", text, re.I)
        if m:
            url = m.group(1)
            return Plan(text, [Step("app.open", {"target": url}, f"Open URL {url}", 1)])
        m = re.search(r"(?:run|start) command (.+)$", text, re.I)
        if m:
            command = m.group(1).strip()
            return Plan(text, [Step("process.start", {"command": command}, f"Run command: {command}", 2, True)])
        if t in {"list processes", "show running processes", "what apps are running"}:
            return Plan(text, [Step("process.list", {}, "List running processes", 0)])
        return Plan(text, [], response="I could not safely map that command. Try 'help', 'system status', 'list my downloads', 'find report in Downloads', 'create folder Project', 'open https://example.com', or 'run command python --version'.")


TOOL_CATALOG = [
    ToolSpec("filesystem.list", "List entries in an approved directory", 0, True),
    ToolSpec("filesystem.search", "Search file names in an approved directory", 0, True),
    ToolSpec("filesystem.read_text", "Read a text file in an approved directory", 0, True),
    ToolSpec("filesystem.create_folder", "Create a folder in an approved directory", 1, True),
    ToolSpec("filesystem.write_text", "Write text to an approved file", 2, False),
    ToolSpec("filesystem.move", "Move a file between approved directories", 2, True),
    ToolSpec("filesystem.delete", "Delete a file in an approved directory", 3, False),
    ToolSpec("process.list", "List running processes", 0, True),
    ToolSpec("process.start", "Start an approved executable", 2, False),
    ToolSpec("process.stop", "Stop a process", 2, False),
    ToolSpec("app.open", "Open a local file, folder, or URL", 1, True),
    ToolSpec("app.close", "Close a matching desktop window", 2, False),
    ToolSpec("window.list", "List visible desktop windows", 0, True),
    ToolSpec("window.focus", "Focus a matching desktop window", 1, True),
    ToolSpec("system.mute", "Mute or unmute system audio", 1, True),
    ToolSpec("system.volume", "Set system audio volume", 1, True),
    ToolSpec("system.lock", "Lock the computer screen", 2, True),
    ToolSpec("system.sleep", "Put the computer to sleep", 3, True),
    ToolSpec("system.shutdown", "Shut down or reboot the computer", 3, False),
    ToolSpec("system.screenshot", "Capture a screenshot to an approved path", 1, True),
    ToolSpec("system.status", "Report local system status", 0, True),
]


class DeskPilotApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("DeskPilot — Personal AI Assistant")
        root.geometry("1050x720")
        root.minsize(820, 560)
        self.audit = AuditLog(DB_PATH)
        self.cancel = threading.Event()
        self.policy = PolicyEngine(DEFAULT_ALLOWED)
        self.tools = Tools(self.policy, self.audit, self.cancel)
        self.llm = LLMClient()
        self.planner = Planner(self.tools, self.llm)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.current_thread: Optional[threading.Thread] = None
        self._build_ui()
        self._log("system", f"DeskPilot ready. Voice replies are local. Speech input backend: {backend_info()}. Text mode works offline without an API key.")
        self.root.after(100, self._drain_events)

    def _build_ui(self):
        # A compact dark dashboard keeps the assistant focused: one primary
        # conversation surface, a visible task state, and safety context.
        self.colors = {
            "bg": "#0b1020", "panel": "#11182b", "panel2": "#172039",
            "border": "#263452", "text": "#eef4ff", "muted": "#91a0bc",
            "accent": "#6c8cff", "accent2": "#48d7b0", "danger": "#ff6f91",
        }
        self.root.configure(bg=self.colors["bg"])
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background=self.colors["bg"])
        style.configure("Panel.TFrame", background=self.colors["panel"])
        style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["text"])
        style.configure("Muted.TLabel", background=self.colors["bg"], foreground=self.colors["muted"])
        style.configure("PanelLabel.TLabel", background=self.colors["panel"], foreground=self.colors["text"])
        style.configure("PanelMuted.TLabel", background=self.colors["panel"], foreground=self.colors["muted"])
        style.configure("Accent.TButton", background=self.colors["accent"], foreground="white", borderwidth=0, padding=(14, 9))
        style.map("Accent.TButton", background=[("active", "#829dff")])
        style.configure("Ghost.TButton", background=self.colors["panel2"], foreground=self.colors["text"], borderwidth=0, padding=(10, 7))
        style.map("Ghost.TButton", background=[("active", self.colors["border"])])
        style.configure("TCheckbutton", background=self.colors["panel"], foreground=self.colors["muted"])
        style.map("TCheckbutton", background=[("active", self.colors["panel"])])

        shell = tk.Frame(self.root, bg=self.colors["bg"])
        shell.pack(fill="both", expand=True)
        sidebar = tk.Frame(shell, bg="#0e1527", width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="◈  DESKPILOT", bg="#0e1527", fg=self.colors["text"], font=("TkDefaultFont", 15, "bold")).pack(anchor="w", padx=20, pady=(24, 5))
        tk.Label(sidebar, text="Your personal computer copilot", bg="#0e1527", fg=self.colors["muted"], font=("TkDefaultFont", 9)).pack(anchor="w", padx=20, pady=(0, 26))
        for label, icon in (("  Command center", "⌂"), ("  Activity log", "◷"), ("  Permissions", "✓"), ("  Voice & offline", "◉")):
            tk.Label(sidebar, text=f"{icon}{label}", bg="#0e1527", fg=self.colors["muted"], anchor="w", font=("TkDefaultFont", 10)).pack(fill="x", padx=20, pady=10)
        tk.Frame(sidebar, bg=self.colors["border"], height=1).pack(fill="x", padx=20, pady=18)
        tk.Label(sidebar, text="SAFE EXECUTION", bg="#0e1527", fg=self.colors["muted"], font=("TkDefaultFont", 8, "bold")).pack(anchor="w", padx=20)
        tk.Label(sidebar, text="●  Policy gate active", bg="#0e1527", fg=self.colors["accent2"], font=("TkDefaultFont", 9)).pack(anchor="w", padx=20, pady=(8, 4))
        tk.Label(sidebar, text="●  Audit trail enabled", bg="#0e1527", fg=self.colors["accent2"], font=("TkDefaultFont", 9)).pack(anchor="w", padx=20)
        tk.Label(sidebar, text="Offline mode available", bg="#0e1527", fg=self.colors["muted"], font=("TkDefaultFont", 8)).pack(anchor="w", padx=20, pady=(16, 0))

        content = tk.Frame(shell, bg=self.colors["bg"])
        content.pack(side="left", fill="both", expand=True, padx=24, pady=20)
        top = tk.Frame(content, bg=self.colors["bg"])
        top.pack(fill="x", pady=(0, 18))
        tk.Label(top, text="Good to see you.", bg=self.colors["bg"], fg=self.colors["text"], font=("TkDefaultFont", 22, "bold")).pack(side="left")
        self.status_var = tk.StringVar(value="Local safe parser")
        tk.Label(top, textvariable=self.status_var, bg=self.colors["bg"], fg=self.colors["accent2"], font=("TkDefaultFont", 10, "bold")).pack(side="right", pady=8)

        cards = tk.Frame(content, bg=self.colors["bg"])
        cards.pack(fill="x", pady=(0, 16))
        self._metric_card(cards, "TASK STATE", "Idle", "task_metric", self.colors["accent"])
        self._metric_card(cards, "VOICE", "Ready", "voice_metric", self.colors["accent2"])
        self._metric_card(cards, "POLICY", "Protected", "policy_metric", self.colors["accent2"])
        self._metric_card(cards, "MODE", "Offline-ready", "mode_metric", self.colors["accent"])

        main = tk.Frame(content, bg=self.colors["bg"])
        main.pack(fill="both", expand=True)
        left = tk.Frame(main, bg=self.colors["panel"], highlightbackground=self.colors["border"], highlightthickness=1)
        left.pack(side="left", fill="both", expand=True, padx=(0, 14))
        tk.Label(left, text="Assistant", bg=self.colors["panel"], fg=self.colors["text"], font=("TkDefaultFont", 13, "bold")).pack(anchor="w", padx=18, pady=(16, 0))
        tk.Label(left, text="Tell me what you want to accomplish.", bg=self.colors["panel"], fg=self.colors["muted"], font=("TkDefaultFont", 9)).pack(anchor="w", padx=18, pady=(2, 8))
        self.chat = scrolledtext.ScrolledText(left, wrap="word", state="disabled", height=22, bg="#0d1425", fg=self.colors["text"], insertbackground="white", selectbackground=self.colors["accent"], relief="flat", borderwidth=0, padx=14, pady=12, font=("TkDefaultFont", 10))
        self.chat.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.chat.tag_configure("user", foreground="#9fb6ff")
        self.chat.tag_configure("assistant", foreground="#a3f1d9")
        input_area = tk.Frame(left, bg=self.colors["panel"])
        input_area.pack(fill="x", padx=12, pady=(0, 12))
        self.command = tk.StringVar()
        self.entry = tk.Entry(input_area, textvariable=self.command, bg=self.colors["panel2"], fg=self.colors["text"], insertbackground="white", relief="flat", font=("TkDefaultFont", 11))
        self.entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 8))
        self.entry.bind("<Return>", lambda _e: self.submit())
        ttk.Button(input_area, text="Send  ↵", style="Accent.TButton", command=self.submit).pack(side="left")
        ttk.Button(input_area, text="Listen  ◉", style="Ghost.TButton", command=self.voice_help).pack(side="left", padx=(6, 0))
        self.speak_replies = tk.BooleanVar(value=True)
        ttk.Checkbutton(input_area, text="Speak", variable=self.speak_replies).pack(side="left", padx=(8, 0))
        self.entry.focus_set()

        right = tk.Frame(main, bg=self.colors["panel"], width=285, highlightbackground=self.colors["border"], highlightthickness=1)
        right.pack(side="left", fill="y")
        right.pack_propagate(False)
        tk.Label(right, text="Quick actions", bg=self.colors["panel"], fg=self.colors["text"], font=("TkDefaultFont", 12, "bold")).pack(anchor="w", padx=16, pady=(16, 4))
        tk.Label(right, text="Start with one tap or type anything.", bg=self.colors["panel"], fg=self.colors["muted"], font=("TkDefaultFont", 9)).pack(anchor="w", padx=16, pady=(0, 10))
        for label, command in (("System status", "system status"), ("List open windows", "list windows"), ("Show my downloads", "list my downloads"), ("Find a file", "find report in Downloads"), ("Open a website", "open https://example.com"), ("Help me", "help")):
            ttk.Button(right, text=label, style="Ghost.TButton", command=lambda c=command: self.quick_action(c)).pack(fill="x", padx=14, pady=3)
        tk.Frame(right, bg=self.colors["border"], height=1).pack(fill="x", padx=16, pady=16)
        tk.Label(right, text="Current task", bg=self.colors["panel"], fg=self.colors["muted"], font=("TkDefaultFont", 9, "bold")).pack(anchor="w", padx=16)
        self.task_var = tk.StringVar(value="Idle — ready for your command")
        tk.Label(right, textvariable=self.task_var, bg=self.colors["panel"], fg=self.colors["text"], wraplength=240, justify="left", font=("TkDefaultFont", 10)).pack(anchor="w", padx=16, pady=(5, 10))
        ttk.Button(right, text="Cancel active task", style="Ghost.TButton", command=self.cancel_task).pack(fill="x", padx=14)
        tk.Frame(right, bg=self.colors["border"], height=1).pack(fill="x", padx=16, pady=16)
        tk.Label(right, text="Approved locations", bg=self.colors["panel"], fg=self.colors["muted"], font=("TkDefaultFont", 9, "bold")).pack(anchor="w", padx=16)
        self.dirs = tk.Listbox(right, height=4, bg=self.colors["panel2"], fg=self.colors["muted"], selectbackground=self.colors["accent"], relief="flat", borderwidth=0, font=("TkDefaultFont", 8))
        self.dirs.pack(fill="x", padx=14, pady=6)
        for p in self.policy.allowed_dirs:
            self.dirs.insert("end", str(p))
        ttk.Button(right, text="+ Add location", style="Ghost.TButton", command=self.add_directory).pack(fill="x", padx=14)

    def _metric_card(self, parent, title, value, attr, color):
        card = tk.Frame(parent, bg=self.colors["panel"], highlightbackground=self.colors["border"], highlightthickness=1)
        card.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Label(card, text=title, bg=self.colors["panel"], fg=self.colors["muted"], font=("TkDefaultFont", 8, "bold")).pack(anchor="w", padx=12, pady=(9, 1))
        var = tk.StringVar(value=value)
        setattr(self, attr, var)
        tk.Label(card, textvariable=var, bg=self.colors["panel"], fg=color, font=("TkDefaultFont", 11, "bold")).pack(anchor="w", padx=12, pady=(0, 9))

    def quick_action(self, command):
        self.command.set(command)
        self.submit()

    def _log(self, role: str, text: str):
        self.audit.message(role, text)
        self.chat.configure(state="normal")
        label = "You" if role == "user" else "DeskPilot" if role == "assistant" else "System"
        tag = role if role in {"user", "assistant"} else "system"
        self.chat.insert("end", f"{label}: {text}\n\n", tag)
        self.chat.configure(state="disabled")
        self.chat.see("end")
        if role == "assistant" and getattr(self, "speak_replies", None) and self.speak_replies.get():
            threading.Thread(target=speak, args=(text,), daemon=True).start()

    def submit(self):
        text = self.command.get().strip()
        if not text or (self.current_thread and self.current_thread.is_alive()):
            return
        self.command.set("")
        self._log("user", text)
        self.cancel.clear()
        self.task_var.set("Understanding command…")
        self.task_metric.set("Planning")
        self.policy_metric.set("Protected")
        self.current_thread = threading.Thread(target=self._worker, args=(text,), daemon=True)
        self.current_thread.start()

    def _worker(self, text: str):
        try:
            self.audit.event("task_received", {"text": text})
            plan = self.planner.make_plan(text)
            if plan.response and not plan.steps:
                self.events.put(("answer", plan.response))
                return
            if not plan.steps:
                self.events.put(("answer", plan.response or "No safe action was generated."))
                return
            self.events.put(("plan", plan))
            results = []
            for step in plan.steps:
                if self.cancel.is_set():
                    raise RuntimeError("Task cancelled")
                decision = self.policy.evaluate(step)
                self.audit.event("policy_decision", {"tool": step.tool, **decision})
                if decision["decision"] == "deny":
                    raise PermissionError(decision["reason"] + " " + decision["preview"])
                if decision["decision"] == "require_confirmation":
                    answer: queue.Queue[bool] = queue.Queue(maxsize=1)
                    self.events.put(("approval", (step, decision, answer)))
                    approved = answer.get(timeout=300)
                    if not approved:
                        raise RuntimeError("User declined the action")
                self.events.put(("step", step.explanation))
                results.append(self.tools.run(step))
            self.events.put(("done", "\n\n".join(results)))
        except Exception as e:
            self.audit.event("task_failed", {"error": str(e)})
            self.events.put(("error", str(e)))

    def _drain_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "answer":
                    self.task_var.set("Completed")
                    self.task_metric.set("Complete")
                    self._log("assistant", payload)
                elif kind == "plan":
                    self.task_var.set(f"Plan created: {len(payload.steps)} step(s)")
                    self.task_metric.set(f"{len(payload.steps)} step(s)")
                elif kind == "step":
                    self.task_var.set(payload)
                    self.task_metric.set("Executing")
                elif kind == "approval":
                    step, decision, answer = payload
                    self.task_var.set("Waiting for approval")
                    self.task_metric.set("Approval")
                    self.policy_metric.set("Review needed")
                    prompt = f"{decision['reason']}\n\n{decision['preview']}\n\nRisk: {PolicyEngine.RISK_NAMES.get(decision['risk'], 'unknown')}"
                    approved = messagebox.askyesno("DeskPilot approval required", prompt, parent=self.root)
                    answer.put(approved)
                elif kind == "done":
                    self.task_var.set("Completed")
                    self.task_metric.set("Complete")
                    self.policy_metric.set("Protected")
                    self._log("assistant", payload)
                    self.refresh_audit()
                elif kind == "error":
                    self.task_var.set("Failed or cancelled")
                    self.task_metric.set("Stopped")
                    self._log("assistant", f"I could not complete the task: {payload}")
                    self.refresh_audit()
                elif kind == "voice":
                    self.command.set(payload)
                    self.task_var.set("Voice command captured")
                    self.voice_metric.set("Captured")
                    self.submit()
                elif kind == "voice_error":
                    self.task_var.set("Voice input unavailable")
                    self.voice_metric.set("Unavailable")
                    messagebox.showwarning("Voice input", payload, parent=self.root)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_events)

    def cancel_task(self):
        self.cancel.set()
        self.task_var.set("Cancellation requested")
        self.audit.event("task_cancel_requested", {})

    def add_directory(self):
        selected = filedialog.askdirectory(parent=self.root)
        if selected:
            p = Path(selected).resolve()
            if p not in self.policy.allowed_dirs:
                self.policy.allowed_dirs.append(p)
                self.dirs.insert("end", str(p))
                self.audit.event("approved_directory_added", {"path": str(p)})

    def refresh_audit(self):
        self.audit_view.configure(state="normal")
        self.audit_view.delete("1.0", "end")
        for ts, event, detail in self.audit.recent(100):
            self.audit_view.insert("end", f"{ts}  {event}\n{detail}\n\n")
        self.audit_view.configure(state="disabled")

    def voice_help(self):
        if self.current_thread and self.current_thread.is_alive():
            return
        self.task_var.set("Listening… speak your command")
        threading.Thread(target=self._voice_worker, daemon=True).start()

    def _voice_worker(self):
        try:
            transcript = listen_once()
            self.events.put(("voice", transcript))
        except Exception as e:
            self.events.put(("voice_error", str(e)))


def cli_main():
    """Run a safe terminal interface when no graphical display is available."""
    audit = AuditLog(DB_PATH)
    cancel = threading.Event()
    policy = PolicyEngine(DEFAULT_ALLOWED)
    tools = Tools(policy, audit, cancel)
    planner = Planner(tools, LLMClient())
    print("DeskPilot terminal mode (no graphical DISPLAY detected). Type 'help' or 'exit'.")
    print("Approved directories:", ", ".join(str(p) for p in policy.allowed_dirs))
    while True:
        try:
            text = input("deskpilot> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return
        if not text:
            continue
        if text.lower() in {"exit", "quit"}:
            print("Goodbye.")
            return
        audit.message("user", text)
        try:
            plan = planner.make_plan(text)
            if plan.response and not plan.steps:
                print("DeskPilot:", plan.response)
                if os.getenv("DESKPILOT_SPEAK_CLI", "0") == "1":
                    threading.Thread(target=speak, args=(plan.response,), daemon=True).start()
                continue
            if not plan.steps:
                print("DeskPilot: No safe action was generated.")
                continue
            results = []
            for step in plan.steps:
                decision = policy.evaluate(step)
                if decision["decision"] == "deny":
                    raise PermissionError(decision["reason"] + " " + decision["preview"])
                if decision["decision"] == "require_confirmation":
                    print("Approval required:", decision["preview"])
                    answer = input("Approve this action? [y/N] ").strip().lower()
                    if answer not in {"y", "yes"}:
                        raise RuntimeError("User declined the action")
                print("Running:", step.explanation)
                results.append(tools.run(step))
            response = "\n\n".join(results)
            audit.message("assistant", response)
            print("DeskPilot:", response)
            if os.getenv("DESKPILOT_SPEAK_CLI", "0") == "1":
                threading.Thread(target=speak, args=(response,), daemon=True).start()
        except Exception as exc:
            audit.event("task_failed", {"error": str(exc)})
            print("DeskPilot error:", exc)


def main():
    # Codespaces, SSH sessions, CI jobs, and servers often have Tk installed but
    # no X11/Wayland display. Falling back to the CLI makes `python run.py`
    # usable instead of crashing with TclError: no display name.
    headless = sys.platform != "win32" and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if headless or os.environ.get("DESKPILOT_HEADLESS") == "1":
        cli_main()
        return
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        if "display" in str(exc).lower():
            print("No graphical display detected; starting terminal mode.", file=sys.stderr)
            cli_main()
            return
        raise
    DeskPilotApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
