from __future__ import annotations

import os
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SUPPORTED_PROVIDERS = {"iac", "aws", "azure", "gcp"}
VERSION_TIMEOUT_SECONDS = 8
DEFAULT_SCAN_TIMEOUT_SECONDS = 1800
MIN_SCAN_TIMEOUT_SECONDS = 60
MAX_SCAN_TIMEOUT_SECONDS = 3600


@dataclass(frozen=True)
class ScannerInfo:
    installed: bool
    executable: str
    version: str
    error: str


@dataclass(frozen=True)
class ScanExecution:
    return_code: int
    timed_out: bool
    cancelled: bool
    stdout: str
    stderr: str


class ProwlerScanner:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self._info_lock = threading.Lock()
        self._cached_info: ScannerInfo | None = None
        self._cached_at = 0.0
        self._active_lock = threading.Lock()
        self._active_processes: dict[str, subprocess.Popen[str]] = {}
        self._container_names: dict[str, str] = {}

    @staticmethod
    def execution_mode() -> str:
        mode = os.environ.get("PROWLER_EXECUTION_MODE", "native").strip().lower()
        return mode if mode in {"native", "docker"} else "invalid"

    @staticmethod
    def docker_image() -> str:
        image = os.environ.get(
            "PROWLER_DOCKER_IMAGE", "prowlercloud/prowler:5.49.0"
        ).strip()
        if not re.fullmatch(r"prowlercloud/prowler:[A-Za-z0-9._-]{1,64}", image):
            return ""
        return image

    @staticmethod
    def docker_executable() -> Path | None:
        configured = os.environ.get("PROWLER_DOCKER_EXECUTABLE", "").strip()
        executable = configured or shutil.which("docker") or ""
        if not executable:
            return None
        path = Path(executable).resolve()
        if path.name.lower() not in {"docker", "docker.exe"} or not path.is_file():
            return None
        return path

    def executable_path(self) -> Path | None:
        configured = os.environ.get("PROWLER_EXECUTABLE", "").strip()
        if configured:
            path = Path(configured)
            if not path.is_absolute():
                path = self.project_root / path
            path = path.resolve()
        else:
            path = (
                shutil.which("prowler.exe")
                or shutil.which("prowler")
                or str(Path(sys.executable).parent / (
                    "prowler.exe" if os.name == "nt" else "prowler"
                ))
            )
            if not Path(path).is_file():
                local_paths = (
                    (
                        self.project_root / ".prowler-venv" / "Scripts" / "prowler.exe",
                        self.project_root / ".venv" / "Scripts" / "prowler.exe",
                    )
                    if os.name == "nt"
                    else (
                        self.project_root / ".prowler-venv" / "bin" / "prowler",
                        self.project_root / ".venv" / "bin" / "prowler",
                    )
                )
                path = next((str(candidate) for candidate in local_paths if candidate.is_file()), "")
            path = Path(path).resolve() if path else None

        if path is None or path.name.lower() not in {"prowler", "prowler.exe"}:
            return None
        return path if path.is_file() else None

    def detect(self, *, refresh: bool = False) -> ScannerInfo:
        with self._info_lock:
            if (
                not refresh
                and self._cached_info is not None
                and time.monotonic() - self._cached_at < 60
            ):
                return self._cached_info

            mode = self.execution_mode()
            if mode == "docker":
                self._cached_info = self._detect_docker_scanner()
            elif mode != "native":
                self._cached_info = ScannerInfo(
                    False,
                    "",
                    "",
                    "PROWLER_EXECUTION_MODE must be 'native' or 'docker'.",
                )
            else:
                path = self.executable_path()
                self._cached_info = self._detect_native_scanner(path)
            self._cached_at = time.monotonic()
            return self._cached_info

    def _detect_native_scanner(self, path: Path | None) -> ScannerInfo:
        if path is None:
            return ScannerInfo(
                installed=False,
                executable="",
                version="",
                error="Scanner not installed or configured.",
            )
        try:
            result = subprocess.run(
                [str(path), "-v"],
                cwd=str(self.project_root),
                env=self._child_environment("iac"),
                capture_output=True,
                text=True,
                timeout=VERSION_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ScannerInfo(
                installed=False,
                executable="",
                version="",
                error="Prowler version check failed.",
            )
        output = (result.stdout or result.stderr).strip().splitlines()
        version = output[0][:120] if output else ""
        if result.returncode != 0 or not version:
            return ScannerInfo(
                False,
                "",
                "",
                "Prowler executable could not report its version.",
            )
        try:
            iac_help = subprocess.run(
                [str(path), "iac", "--help"],
                cwd=str(self.project_root),
                env=self._child_environment("iac"),
                capture_output=True,
                text=True,
                timeout=VERSION_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ScannerInfo(
                False,
                "",
                version,
                "Prowler IaC provider help could not be verified.",
            )
        help_text = f"{iac_help.stdout}\n{iac_help.stderr}".lower()
        required_options = ("--scan-path", "--output-formats", "--output-directory")
        if iac_help.returncode != 0 or any(option not in help_text for option in required_options):
            return ScannerInfo(
                False,
                "",
                version,
                "Installed Prowler does not expose the required IaC scan options.",
            )
        if "json-ocsf" not in help_text:
            return ScannerInfo(
                False,
                "",
                version,
                "Installed Prowler IaC provider does not advertise json-ocsf output.",
            )
        return ScannerInfo(True, str(path), version, "")

    def _detect_docker_scanner(self) -> ScannerInfo:
        docker_path = self.docker_executable()
        image = self.docker_image()
        if docker_path is None or not image:
            return ScannerInfo(
                False,
                "",
                "",
                "Scanner not installed or configured.",
            )
        environment = self._child_environment("iac")
        try:
            inspected = subprocess.run(
                [str(docker_path), "image", "inspect", image],
                cwd=str(self.project_root),
                env=environment,
                capture_output=True,
                text=True,
                timeout=VERSION_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
            if inspected.returncode != 0:
                return ScannerInfo(
                    False,
                    "",
                    "",
                    "Prowler Docker image is not available locally.",
                )
            result = subprocess.run(
                [
                    str(docker_path),
                    "run",
                    "--pull=never",
                    "--rm",
                    "--entrypoint",
                    "prowler",
                    image,
                    "-v",
                ],
                cwd=str(self.project_root),
                env=environment,
                capture_output=True,
                text=True,
                timeout=VERSION_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ScannerInfo(
                False,
                "",
                "",
                "Prowler Docker runtime could not report its version.",
            )
        output = (result.stdout or result.stderr).strip().splitlines()
        version = output[0][:120] if output else ""
        if result.returncode == 0 and version:
            return ScannerInfo(True, str(docker_path), version, "")
        return ScannerInfo(
            False,
            "",
            "",
            "Prowler Docker image could not report its version.",
        )

    def build_command(
        self,
        *,
        scan_id: str = "manual",
        provider: str,
        output_directory: Path,
    ) -> list[str]:
        if provider not in SUPPORTED_PROVIDERS:
            raise ValueError("Unsupported Prowler provider.")
        info = self.detect()
        if not info.installed:
            raise FileNotFoundError(info.error)

        if self.execution_mode() == "docker":
            return self._build_docker_command(
                scan_id=scan_id,
                provider=provider,
                output_directory=output_directory,
            )

        command = [
            info.executable,
            provider,
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            str(output_directory),
        ]
        if provider == "iac":
            command.extend(["--scan-path", str(self.project_root)])
        return command

    def _build_docker_command(
        self,
        *,
        scan_id: str,
        provider: str,
        output_directory: Path,
    ) -> list[str]:
        docker_path = self.docker_executable()
        image = self.docker_image()
        if docker_path is None or not image:
            raise FileNotFoundError("Prowler Docker runtime is not configured.")

        source_root = self.project_root.as_posix()
        report_root = output_directory.resolve().as_posix()
        if "," in source_root or "," in report_root:
            raise ValueError("Docker bind paths may not contain commas.")
        name = f"metaguard-prowler-{scan_id}"
        command = [
            str(docker_path),
            "run",
            "--pull=never",
            "--rm",
            "--name",
            name,
            "--mount",
            f"type=bind,source={source_root},target=/workspace,readonly",
            "--mount",
            f"type=bind,source={report_root},target=/home/prowler/output",
            "--env",
            "AWS_EC2_METADATA_DISABLED=true",
        ]
        environment_names = {
            "aws": (
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_REGION",
                "AWS_DEFAULT_REGION",
            ),
            "azure": (
                "AZURE_CLIENT_ID",
                "AZURE_CLIENT_SECRET",
                "AZURE_TENANT_ID",
                "AZURE_SUBSCRIPTION_ID",
            ),
            "gcp": ("GOOGLE_CLOUD_PROJECT",),
            "iac": (),
        }[provider]
        for name_key in environment_names:
            if os.environ.get(name_key):
                command.extend(["--env", name_key])

        if provider == "aws":
            role_arn = os.environ.get("AWS_ROLE_ARN", "").strip()
            token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "").strip()
            if role_arn and token_file:
                token_path = Path(token_file).resolve()
                if not token_path.is_file():
                    raise ValueError("AWS web identity token file is not available.")
                token_source = token_path.as_posix()
                if "," in token_source:
                    raise ValueError("AWS token file path may not contain commas.")
                command.extend(
                    [
                        "--mount",
                        f"type=bind,source={token_source},target=/run/secrets/aws-web-identity-token,readonly",
                        "--env",
                        "AWS_ROLE_ARN",
                        "--env",
                        "AWS_WEB_IDENTITY_TOKEN_FILE=/run/secrets/aws-web-identity-token",
                    ]
                )

        if provider == "gcp":
            credentials = os.environ.get(
                "GOOGLE_APPLICATION_CREDENTIALS", ""
            ).strip()
            if credentials:
                credentials_path = Path(credentials).resolve()
                if not credentials_path.is_file():
                    raise ValueError("GCP credential file is not available.")
                credentials_source = credentials_path.as_posix()
                if "," in credentials_source:
                    raise ValueError("GCP credential file path may not contain commas.")
                command.extend(
                    [
                        "--mount",
                        f"type=bind,source={credentials_source},target=/run/secrets/gcp-credentials.json,readonly",
                        "--env",
                        "GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/gcp-credentials.json",
                    ]
                )

        command.extend(
            [
                image,
                provider,
                "--output-formats",
                "json-ocsf",
                "--output-directory",
                "/home/prowler/output",
            ]
        )
        if provider == "iac":
            command.extend(["--scan-path", "/workspace"])
        self._container_names[scan_id] = name
        return command

    @staticmethod
    def scan_timeout_seconds() -> int:
        value = os.environ.get("PROWLER_SCAN_TIMEOUT_SECONDS", "").strip()
        if not value:
            return DEFAULT_SCAN_TIMEOUT_SECONDS
        try:
            timeout = int(value)
        except ValueError:
            return DEFAULT_SCAN_TIMEOUT_SECONDS
        return min(max(timeout, MIN_SCAN_TIMEOUT_SECONDS), MAX_SCAN_TIMEOUT_SECONDS)

    @staticmethod
    def _child_environment(provider: str) -> dict[str, str]:
        shared_names = {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "LANG",
            "LC_ALL",
        }
        provider_names = {
            "aws": {
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_DEFAULT_REGION",
                "AWS_REGION",
                "AWS_ROLE_ARN",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
            },
            "azure": {
                "AZURE_CLIENT_ID",
                "AZURE_CLIENT_SECRET",
                "AZURE_TENANT_ID",
                "AZURE_SUBSCRIPTION_ID",
            },
            "gcp": {
                "GOOGLE_APPLICATION_CREDENTIALS",
                "GOOGLE_CLOUD_PROJECT",
                "CLOUDSDK_AUTH_ACCESS_TOKEN",
            },
            "iac": set(),
        }.get(provider, set())
        allowed = shared_names | provider_names
        environment = {key: value for key, value in os.environ.items() if key in allowed}
        environment["AWS_EC2_METADATA_DISABLED"] = "true"
        environment["AWS_CONFIG_FILE"] = os.devnull
        environment["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
        return environment

    def execute(
        self,
        *,
        scan_id: str,
        provider: str,
        output_directory: Path,
        cancel_event: threading.Event,
        on_process: Any,
    ) -> ScanExecution:
        command = self.build_command(
            scan_id=scan_id,
            provider=provider,
            output_directory=output_directory,
        )
        timeout = self.scan_timeout_seconds()
        creation_flags = (
            subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        )
        try:
            process = subprocess.Popen(
                command,
                cwd=str(self.project_root),
                env=self._child_environment(provider),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                creationflags=creation_flags,
                start_new_session=os.name != "nt",
            )
        except OSError:
            raise RuntimeError("Prowler could not be started.") from None

        with self._active_lock:
            self._active_processes[scan_id] = process
        on_process(process)
        deadline = time.monotonic() + timeout
        timed_out = False
        cancelled = False
        stdout = ""
        stderr = ""
        try:
            while True:
                if cancel_event.is_set():
                    cancelled = True
                    self._terminate_process(process, scan_id)
                elif time.monotonic() >= deadline:
                    timed_out = True
                    self._terminate_process(process, scan_id)
                try:
                    stdout, stderr = process.communicate(timeout=0.5)
                    break
                except subprocess.TimeoutExpired:
                    if timed_out or cancelled:
                        self._terminate_process(process, scan_id)
            return ScanExecution(
                return_code=process.returncode if process.returncode is not None else -1,
                timed_out=timed_out,
                cancelled=cancelled,
                stdout=stdout or "",
                stderr=stderr or "",
            )
        finally:
            with self._active_lock:
                self._active_processes.pop(scan_id, None)
                self._container_names.pop(scan_id, None)

    def _terminate_process(
        self,
        process: subprocess.Popen[str],
        scan_id: str,
    ) -> None:
        if process.poll() is not None:
            return
        try:
            container_name = self._container_names.get(scan_id)
            if container_name and self.execution_mode() == "docker":
                docker_path = self.docker_executable()
                if docker_path:
                    try:
                        subprocess.run(
                            [
                                str(docker_path),
                                "stop",
                                "--time",
                                "3",
                                container_name,
                            ],
                            env=self._child_environment("iac"),
                            capture_output=True,
                            text=True,
                            timeout=5,
                            check=False,
                            shell=False,
                        )
                    except (OSError, subprocess.TimeoutExpired):
                        pass
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                return

    def cancel(self, scan_id: str) -> bool:
        with self._active_lock:
            process = self._active_processes.get(scan_id)
        if process is None:
            return False
        self._terminate_process(process, scan_id)
        return True
