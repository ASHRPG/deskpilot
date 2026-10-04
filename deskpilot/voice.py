from __future__ import annotations


def listen_once(timeout: int = 5, phrase_time_limit: int = 15) -> str:
    """Capture one spoken command when SpeechRecognition/PyAudio are installed.

    The dependency is optional so DeskPilot remains usable on machines without a
    microphone backend. Recognition uses the configured SpeechRecognition engine.
    """
    try:
        import speech_recognition as sr
    except ImportError as exc:
        raise RuntimeError("Voice input is optional. Install requirements-voice.txt first.") from exc

    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        recognizer.adjust_for_ambient_noise(source, duration=0.4)
        audio = recognizer.listen(source, timeout=timeout, phrase_time_limit=phrase_time_limit)
    try:
        return recognizer.recognize_google(audio)
    except sr.UnknownValueError as exc:
        raise RuntimeError("I could not understand the audio.") from exc
    except sr.RequestError as exc:
        raise RuntimeError(f"Speech recognition service unavailable: {exc}") from exc


def speak(text: str) -> None:
    """Best-effort local speech output; silently does nothing if unavailable."""
    try:
        import pyttsx3
        engine = pyttsx3.init()
        engine.say(text[:1000])
        engine.runAndWait()
    except Exception:
        return
