# 🔐 pii-guard

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
```

📖 Uso

# Escanear um diretório

pii-guard src/

# Escanear um arquivo específico

pii-guard exemplo.py

# Filtrar apenas findings críticos e altos

pii-guard src/ --severity high

# Gerar relatório em JSON

pii-guard src/ --format json --output relatorio.json

# Resumo compacto

pii-guard src/ --format summary

Opções:
--format, -f - Formato de saída: table (padrão), json, summary
--output, -o - Salvar relatório JSON em arquivo
--severity, -s - Filtrar por severidade mínima: critical, high, medium, low, info

🔍 O que o scanner detecta

Regra Severidade Descrição
AWS_ACCESS_KEY CRITICAL AWS Access Key ID exposta
AWS_SECRET_KEY CRITICAL AWS Secret Access Key exposta
GITHUB_TOKEN CRITICAL Token do GitHub exposto
GOOGLE_API_KEY CRITICAL Google API Key exposta
GENERIC_PASSWORD HIGH Senha hardcoded
PRIVATE_KEY CRITICAL Chave privada exposta
JWT_TOKEN HIGH Token JWT exposto
CONNECTION_STRING CRITICAL String de conexão com credenciais

PII (8 padrões)

Regra Severidade Descrição

BR_CPF CRITICAL CPF exposto
BR_CNPJ MEDIUM CNPJ exposto
EMAIL_ADDRESS HIGH E-mail pessoal exposto
BR_PHONE MEDIUM Telefone brasileiro exposto
BR_RG CRITICAL RG exposto
BR_CEP LOW CEP exposto
CREDIT_CARD CRITICAL Cartão de crédito exposto
FULL_NAME_HINT MEDIUM Nome pessoal em variável

🏗️ Arquitetura

pii-guard/
├── src/
│ └── pii_guard/
│ ├── **init**.py # Versão do pacote
│ ├── models.py # Modelos de dados (Finding, ScanResult)
│ ├── scanner.py # Scanner principal (coordena detectores)
│ ├── cli.py # Interface de linha de comando
│ └── detectors/
│ ├── **init**.py
│ ├── secrets.py # Detector de secrets (8 padrões)
│ └── pii.py # Detector de PII (8 padrões)
├── tests/ # Testes automatizados
├── pyproject.toml # Configuração do pacote
├── requirements.txt # Dependências
└── .gitignore

⚖️ Mapeamento LGPD

Cada finding mapeia o problema detectado ao artigo correspondente da LGPD:

- Art. 5 — Direitos do titular de dados pessoais
- Art. 7 — Tratamento de dados pessoais
- Art. 11 — Dados sensíveis e identificação pessoal
- Art. 46 — Medidas de segurança

E ao controle da ISO 27001:

- A.8.5 — Autenticação segura
- A.8.10 — Informação para supressão de dados
- A.8.24 — Criptografia
