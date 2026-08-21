"""
Scanner principal do pii-guard.

Coordena os detectores de secrets e PII, varre diretórios
e consolida os resultados em um ScanResult.
"""

from pathlib import Path

from pii_guard.models import Finding, ScanResult
from pii_guard.detectors import secrets as secrets_detector
from pii_guard.detectors import pii as pii_detector

# Extensões de arquivo que o scanner analisa
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".sql"}

# Diretórios que devem ser ignorados
IGNORE_DIRS = {".venv", "venv", "__pycache__", ".git", "node_modules", ".env", "dist", "build", ".tox", ".pytest_cache"}

class Scanner:
    """Scanner principal que coordena os detectores."""

    def __init__(self, target_path: str | Path):
        self.target_path = Path(target_path)
        if not self.target_path.exists():
            raise FileNotFoundError(f"Caminho não encontrado: {self.target_path}")

    def _should_scan(self, file_path: Path) -> bool:
        """Verifica se o arquivo deve ser escaneado."""
        parts = set(file_path.parts)
        if parts & IGNORE_DIRS:
            return False
        if file_path.suffix not in SUPPORTED_EXTENSIONS:
            return False
        return True

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Escaneia um arquivo individual com todos os detectores."""
        findings: list[Finding] = []
        findings.extend(secrets_detector.scan_file(file_path))
        if file_path.suffix == ".py":
            findings.extend(pii_detector.scan_file(file_path))
        return findings

    def scan(self) -> ScanResult:
        """Executa o scan completo no caminho configurado.

        Returns:
            ScanResult com todos os findings consolidados.
        """
        all_findings: list[Finding] = []
        files_scanned = 0

        if self.target_path.is_file():
            if self._should_scan(self.target_path):
                all_findings.extend(self._scan_file(self.target_path))
                files_scanned = 1
        else:
            for file_path in self.target_path.rglob("*"):
                if file_path.is_file() and self._should_scan(file_path):
                    all_findings.extend(self._scan_file(file_path))
                    files_scanned += 1

        return ScanResult(
            target_path=str(self.target_path),
            files_scanned=files_scanned,
            findings=all_findings,
        )