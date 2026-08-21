"""
Detector de dados pessoais (PII) em código-fonte.

Identifica CPF, e-mail, telefone, RG e outros dados
sensíveis que não deveriam estar hardcoded no código,
mapeando cada finding a artigos específicos da LGPD.
"""

import re
from pathlib import Path

from pii_guard.models import Finding, FindingType, Severity

# Padrões de detecção de PII
# (rule_id, descrição, regex, severidade, artigo LGPD, controle ISO, recomendação)
PII_PATTERNS: list[tuple[str, str, str, Severity, str, str, str]] = [
    (
        "BR_CPF",
        "CPF exposto no código",
        r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b',
        Severity.CRITICAL,
        "Art. 11 - Dados sensíveis e identificação pessoal",
        "A.8.10 - Informação para supressão de dados",
        "Remova o CPF do código e use pseudonimização",
    ),
    (
        "BR_CNPJ",
        "CNPJ exposto no código",
        r'\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b',
        Severity.MEDIUM,
        "Art. 7 - Dados pessoais de pessoa jurídica",
        "A.8.10 - Informação para supressão de dados",
        "Use variável de ambiente para dados de empresa",
    ),
    (
        "EMAIL_ADDRESS",
        "Endereço de e-mail pessoal exposto no código",
        r'\b[a-zA-Z0-9._%+-]+@(?!example\.com|test\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        Severity.HIGH,
        "Art. 5 - Direitos do titular de dados pessoais",
        "A.8.10 - Informação para supressão de dados",
        "Use variável de configuração ou e-mail genérico",
    ),
    (
        "BR_PHONE",
        "Número de telefone brasileiro exposto no código",
        r'\b(?:\+55\s?)?\(?\d{2}\)?\s?\d{4,5}-?\d{4}\b',
        Severity.MEDIUM,
        "Art. 7 - Tratamento de dados pessoais",
        "A.8.10 - Informação para supressão de dados",
        "Remova o número e use sistema de contato",
    ),
    (
        "BR_RG",
        "RG (Registro Geral) exposto no código",
        r'\b(?:RG|rg|R\.G\.?)\s*:?\s*\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Xx]\b',
        Severity.CRITICAL,
        "Art. 11 - Dados sensíveis e identificação pessoal",
        "A.8.10 - Informação para supressão de dados",
        "Remova o RG do código imediatamente",
    ),
    (
        "BR_CEP",
        "CEP (endereço) exposto no código",
        r'\b\d{5}-\d{3}\b',
        Severity.LOW,
        "Art. 7 - Tratamento de dados pessoais",
        "A.8.10 - Informação para supressão de dados",
        "Use variável de configuração para endereços",
    ),
    (
        "CREDIT_CARD",
        "Número de cartão de crédito exposto no código",
        r'\b(?:\d[ -]*?){13,16}\b',
        Severity.CRITICAL,
        "Art. 11 - Dados financeiros sensíveis",
        "A.8.24 - Criptografia",
        "Remova imediatamente e use gateway de pagamento",
    ),
    (
        "FULL_NAME_HINT",
        "Possível nome pessoal em variável de dados",
        r'(?:nome|name|cliente|paciente|usuario)\s*[=:]\s*["\'][A-Z][a-z]+\s+[A-Z][a-z]+["\']',
        Severity.MEDIUM,
        "Art. 5 - Direitos do titular de dados pessoais",
        "A.8.10 - Informação para supressão de dados",
        "Carregue nomes de base de dados, não hardcoded",
    ),
]

def scan_file(file_path: Path) -> list[Finding]:
    """Escaneia um único arquivo em busca de PII.

    Args:
        file_path: Caminho do arquivo a ser analisado.

    Returns:
        Lista de findings encontrados no arquivo.
    """
    findings: list[Finding] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return findings

    for rule_id, description, pattern, severity, lgpd_article, iso_control, recommendation in PII_PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE)
        for match in regex.finditer(content):
            line_number = content[:match.start()].count("\n") + 1
            findings.append(
                Finding(
                    file_path=str(file_path),
                    line_number=line_number,
                    finding_type=FindingType.PII,
                    severity=severity,
                    rule_id=rule_id,
                    description=description,
                    matched_text=match.group(),
                    lgpd_article=lgpd_article,
                    iso_control=iso_control,
                    recommendation=recommendation,
                )
            )

    return findings

def scan_directory(target_path: Path) -> list[Finding]:
    """Escaneia todos os arquivos .py em um diretório recursivamente.

    Args:
        target_path: Caminho do diretório a ser analisado.

    Returns:
        Lista de findings encontrados em todos os arquivos.
    """
    all_findings: list[Finding] = []

    for py_file in target_path.rglob("*.py"):
        if ".venv" in str(py_file) or "__pycache__" in str(py_file):
            continue
        all_findings.extend(scan_file(py_file))

    return all_findings