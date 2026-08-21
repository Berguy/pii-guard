"""
Testes automatizados dos detectores de secrets e PII.
"""

import pytest
from pii_guard.detectors import secrets as secrets_detector
from pii_guard.detectors import pii as pii_detector
from pii_guard.models import Severity, FindingType

def test_detects_aws_access_key(tmp_path):
    """Deve detectar AWS Access Key ID."""
    file = tmp_path / "test.py"
    file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    findings = secrets_detector.scan_file(file)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS_ACCESS_KEY"
    assert findings[0].severity == Severity.CRITICAL

def test_detects_github_token(tmp_path):
    """Deve detectar token do GitHub."""
    file = tmp_path / "test_gh.py"
    file.write_text('TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n', encoding="utf-8")
    findings = secrets_detector.scan_file(file)
    assert len(findings) == 1
    assert findings[0].rule_id == "GITHUB_TOKEN"

def test_detects_password(tmp_path):
    """Deve detectar senha hardcoded."""
    file = tmp_path / "test_pwd.py"
    file.write_text('password = "minhasenha123"\n', encoding="utf-8")
    findings = secrets_detector.scan_file(file)
    assert len(findings) == 1
    assert findings[0].rule_id == "GENERIC_PASSWORD"
    assert findings[0].severity == Severity.HIGH

def test_detects_cpf(tmp_path):
    """Deve detectar CPF."""
    file = tmp_path / "test_cpf.py"
    file.write_text('cpf = "123.456.789-00"\n', encoding="utf-8")
    findings = pii_detector.scan_file(file)
    cpf_findings = [f for f in findings if f.rule_id == "BR_CPF"]
    assert len(cpf_findings) == 1
    assert cpf_findings[0].severity == Severity.CRITICAL

def test_detects_email(tmp_path):
    """Deve detectar e-mail pessoal."""
    file = tmp_path / "test_email.py"
    file.write_text('email = "joao.silva@empresa.com.br"\n', encoding="utf-8")
    findings = pii_detector.scan_file(file)
    email_findings = [f for f in findings if f.rule_id == "EMAIL_ADDRESS"]
    assert len(email_findings) == 1
    assert email_findings[0].severity == Severity.HIGH

def test_detects_credit_card(tmp_path):
    """Deve detectar número de cartão de crédito."""
    file = tmp_path / "test_card.py"
    file.write_text('cartao = "4539 1488 0343 6467"\n', encoding="utf-8")
    findings = pii_detector.scan_file(file)
    card_findings = [f for f in findings if f.rule_id == "CREDIT_CARD"]
    assert len(card_findings) == 1
    assert card_findings[0].severity == Severity.CRITICAL

def test_clean_file_no_findings(tmp_path):
    """Arquivo limpo não deve gerar findings."""
    file = tmp_path / "test_clean.py"
    file.write_text('import os\nx = 42\nprint("hello")\n', encoding="utf-8")
    secrets_findings = secrets_detector.scan_file(file)
    pii_findings = pii_detector.scan_file(file)
    assert len(secrets_findings) == 0
    assert len(pii_findings) == 0

def test_finding_has_lgpd_article(tmp_path):
    """Todo finding deve ter artigo da LGPD preenchido."""
    file = tmp_path / "test_lgpd.py"
    file.write_text('cpf = "123.456.789-00"\n', encoding="utf-8")
    findings = pii_detector.scan_file(file)
    for f in findings:
        assert f.lgpd_article != ""
        assert "Art." in f.lgpd_article