"""
Detector de secrets hardcoded em código.

Identifica API keys, senhas, tokens e credenciais
que foram inseridas diretamente no código-fonte,
mapeando cada finding a artigos da LGPD.
"""

import re
from pathlib import Path

from pii_guard.models import Finding, FindingType, Severity

# Padrões de detecção de secrets
# Cada padrão contem: (rule_id, descrição, regex, severidade, artigo LGPD, controle ISO, recomendação)
SECRET_PATTERNS: list[tuple[str, str, str, Severity, str, str, str]] = [
    (
        "AWS_ACCESS_KEY",
        "AWS Access Key ID exposta no código",
        r'AKIA[0-9A-Z]{16}',
        Severity.CRITICAL,
        "Art. 46 - Medidas de segurança",
        "A.8.5 - Autenticação segura",
        "Mova a chave para variável de ambiente ou AWS IAM Role",
    ),
    (
        "AWS_SECRET_KEY",
        "AWS Secret Access Key exposta no código",
        r'aws_secret_access_key\s*=\s*["\'][^"\']{40}["\']',
        Severity.CRITICAL,
        "Art. 46 - Medidas de segurança",
        "A.8.5 - Autenticação segura",
        "Use AWS SDK com credenciais gerenciadas",
    ),
    (
        "GITHUB_TOKEN",
        "Token do GitHub exposto no código",
        r'gh[pousr]_[A-Za-z0-9]{36}',
        Severity.CRITICAL,
        "Art. 46 - Medidas de segurança",
        "A.8.5 - Autenticação segura",
        "Revogue o token e use GitHub Actions secrets",
    ),
    (
        "GOOGLE_API_KEY",
        "Google API Key exposta no código",
        r'AIza[0-9A-Za-z\-_]{35}',
        Severity.CRITICAL,
        "Art. 46 - Medidas de segurança",
        "A.8.5 - Autenticação segura",
        "Use Google Cloud Secret Manager",
    ),
    (
        "GENERIC_PASSWORD",
        "Senha hardcoded no código",
        r'(?:password|passwd|pwd|senha)\s*[=:]\s*["\'][^"\']{6,}["\']',
        Severity.HIGH,
        "Art. 46 - Medidas de segurança",
        "A.8.5 - Autenticação segura",
        "Use variável de ambiente ou cofre de segredos",
    ),
    (
        "PRIVATE_KEY",
        "Chave privada exposta no código",
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----',
        Severity.CRITICAL,
        "Art. 46 - Medidas de segurança",
        "A.8.24 - Criptografia",
        "Remova a chave do código e use cofre de segredos",
    ),
    (
        "JWT_TOKEN",
        "Token JWT exposto no código",
        r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        Severity.HIGH,
        "Art. 46 - Medidas de segurança",
        "A.8.5 - Autenticação segura",
        "Revogue o token e use armazenamento seguro",
    ),
    (
        "CONNECTION_STRING",
        "String de conexão com credenciais exposta",
        r'(?:mongodb|postgres|mysql|redis)://[^:\s]+:[^@\s]+@',
        Severity.CRITICAL,
        "Art. 46 - Medidas de segurança",
        "A.8.5 - Autenticação segura",
        "Use variável de ambiente para string de conexão",
    ),
]

def scan_file(file_path: Path) -> list[Finding]:
    """Escaneia um único arquivo em busca de secrets.

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

    for rule_id, description, pattern, severity, lgpd_article, iso_control, recommendation in SECRET_PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE)
        for match in regex.finditer(content):
            line_number = content[:match.start()].count("\n") + 1
            findings.append(
                Finding(
                    file_path=str(file_path),
                    line_number=line_number,
                    finding_type=FindingType.SECRET,
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
        # Ignora o próprio código do scanner
        if ".venv" in str(py_file) or "__pycache__" in str(py_file):
            continue
        all_findings.extend(scan_file(py_file))

    return all_findings