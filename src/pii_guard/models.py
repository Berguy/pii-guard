"""
Modelos de dados do pii-guard.

Define as estruturas usadas para representar
findings (descobertas) do scanner.
"""

from enum import Enum
from pydantic import BaseModel, Field

class Severity(str, Enum):
    """Níveis de severidade de um finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingType(str, Enum):
    """Tipos de dados que o scanner detecta."""
    SECRET = "secret"
    PII = "pii"
    VULNERABILITY = "vulnerability"

class Finding(BaseModel):
    """Representa uma descoberta do scanner.

    Cada finding mapeia um problema detectado no código
    a um artigo específico da LGPD.
    """
    file_path: str = Field(..., description="Caminho do arquivo analisado")
    line_number: int = Field(..., description="Linha onde o problema foi encontrado")
    finding_type: FindingType = Field(..., description="Tipo do finding")
    severity: Severity = Field(..., description="Nível de severidade")
    rule_id: str = Field(..., description="Identificador da regra que disparou")
    description: str = Field(..., description="Descrição do problema")
    matched_text: str = Field(..., description="Texto que disparou a detecção (mascarado)")
    lgpd_article: str = Field(..., description="Artigo da LGPD relacionado")
    iso_control: str = Field(default="", description="Controle ISO 27001 relacionado")
    recommendation: str = Field(..., description="Como corrigir")

    def mask_sensitive(self) -> str:
        """Mascara o texto sensível para exibição segura no relatório."""
        if len(self.matched_text) <= 4:
            return "*" * len(self.matched_text)
        return self.matched_text[:2] + "*" * (len(self.matched_text) - 4) + self.matched_text[-2:]

class ScanResult(BaseModel):
    """Resultado completo de um scan."""
    target_path: str = Field(..., description="Caminho escaneado")
    files_scanned: int = Field(default=0, description="Total de arquivos analisados")
    findings: list[Finding] = Field(default_factory=list, description="Lista de findings")

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)