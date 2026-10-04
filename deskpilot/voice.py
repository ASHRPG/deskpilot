from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

_speech_lock = threading.Lock()


def _capture(timeout: int, phrase_time_limit: int):
    try:
        import speech_recognition as sr
    except ImportError as exc:
        raise RuntimeError("Install voice dependencies with: python3 -m pip install -r requirements-voice.txt") from exc
    recognizer = sr.Recognizer()
    try:
        with sr.Microphone() as source:
            recognizer.adjust_for_ambient_noise(source, duration=0.4)
            return sr, recognizer.listen(source, timeout=timeout, phrase_time_limit=phrase_time_limit)
    except OSError as exc:
        raise RuntimeError("No usable microphone was found. Check microphone permissions and PyAudio.") from exc


def _recognize_vosk(sr, audio, model_path: str) -> str:
    try:
        import vosk
    except ImportError as exc:
        raise RuntimeError("Vosk model configured but vosk is not installed. Install requirements-voice.txt.") from exc
    model = vosk.Model(model_path)
    recognizer = vosk.KaldiRecognizer(model, 16000)
    raw = audio.get_raw_data(convert_rate=16000, convert_width=2)
    recognizer.AcceptWaveform(raw)
    result = json.loads(recognizer.FinalResult())
    return result.get("text", "").strip()


def _recognize_whisper(audio, model_name: str) -> str:
    try:
        from faster_whisper import WhisperModel
    except ImportError as exc:
        raise RuntimeError("Whisper model configured but faster-whisper is not installed. Install requirements-voice.txt.") from exc
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        f.write(audio.get_wav_data())
        wav_path = f.name
    try:
        model = WhisperModel(model_name, device=os.getenv("DESKPILOT_WHISPER_DEVICE", "cpu"), compute_type=os.getenv("DESKPILOT_WHISPER_COMPUTE", "int8"))
        segments, _ = model.transcribe(wav_path, vad_filter=True)
        return " ".join(s.text.strip() for s in segments).strip()
    finally:
        Path(wav_path).unlink(missing_ok=True)


def listen_once(timeout: int = 5, phrase_time_limit: int = 15) -> str:
    """Capture one command and recognize it locally when configured.

    Backend priority: Vosk, faster-whisper, then SpeechRecognition's online
    fallback. Set DESKPILOT_VOSK_MODEL or DESKPILOT_WHISPER_MODEL to guarantee
    that speech recognition is offline.
    """
    sr, audio = _capture(timeout, phrase_time_limit)
    vosk_model = os.getenv("DESKPILOT_VOSK_MODEL")
    whisper_model = os.getenv("DESKPILOT_WHISPER_MODEL")
    if vosk_model:
        text = _recognize_vosk(sr, audio, vosk_model)
    elif whisper_model:
        text = _recognize_whisper(audio, whisper_model)
    else:
        try:
            text = sr.Recognizer().recognize_google(audio)
        except sr.UnknownValueError as exc:
            raise RuntimeError("I could not understand the audio.") from exc
        except sr.RequestError as exc:
            raise RuntimeError("Online speech recognition is unavailable. Configure DESKPILOT_VOSK_MODEL or DESKPILOT_WHISPER_MODEL for offline speech.") from exc
    if not text:
        raise RuntimeError("No speech was recognized.")
    return text


def speak(text: str) -> None:
    """Speak a response locally without sending it to a cloud service."""
    text = " ".join(str(text).split())[:2000]
    if not text:
        return
    with _speech_lock:
        try:
            import pyttsx3
            engine = pyttsx3.init()
            engine.setProperty("rate", int(os.getenv("DESKPILOT_TTS_RATE", "175")))
            engine.say(text)
            engine.runAndWait()
            return
        except Exception:
            pass
        for command in ("espeak", "espeak-ng"):
            if shutil.which(command):
                subprocess.run([command, text], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return


def backend_info() -> str:
    if os.getenv("DESKPILOT_VOSK_MODEL"):
        return "offline Vosk"
    if os.getenv("DESKPILOT_WHISPER_MODEL"):
        return "offline Whisper"
    return "online fallback (configure Vosk or Whisper for offline voice)"
