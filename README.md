# 🔐 PII Guard

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![CI](https://github.com/Berguy/pii-guard/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)

Scanner de **secrets** e **PII** (dados pessoais) para conformidade com a **LGPD** e **ISO 27001**.

Ferramenta de linha de comando que analisa código-fonte em busca de credenciais hardcoded e dados pessoais expostos, mapeando cada finding ao artigo correspondente da LGPD e ao controle da ISO 27001.

---

## 🚀 Instalação

```bash
git clone https://github.com/Berguy/pii-guard.git
cd pii-guard
python -m venv .venv
source .venv/Scripts/activate      # Windows
# source .venv/bin/activate         # Linux/Mac
pip install -e .
