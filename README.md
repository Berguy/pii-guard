# PII Guard
 
![License](https://img.shields.io/badge/license-MIT-blue)
![CI](https://img.shields.io/badge/CI-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
 
**Scanner de secrets e PII para conformidade com a LGPD e ISO 27001.**
 
Ferramenta de linha de comando que analisa código-fonte em busca de credenciais hardcoded e dados pessoais expostos, mapeando cada finding ao artigo correspondente da LGPD e ao controle da ISO 27001.
 
---
 
## Por que este projeto existe
 
Vazamento de dado pessoal raramente começa com um ataque sofisticado. Na maioria dos casos, começa com uma linha de código: uma senha de banco escrita direto no arquivo, um CPF de cliente num script de teste, uma chave de API commitada no repositório.
 
O problema é que esses achados não aparecem em revisão de código. Eles passam despercebidos porque ninguém sabe exatamente o que procurar — e menos ainda qual obrigação legal cada achado viola.
 
O PII Guard resolve as duas pontas: encontra o problema e diz qual artigo da LGPD e qual controle da ISO 27001 ele fere. Um scanner de secrets existe aos montes; um que traduz o achado em obrigação normativa é outra categoria de ferramenta.
 
## O que já funciona
 
### Detecção de secrets (8 regras)
 
| Regra | O que detecta | Severidade |
|---|---|---|
| `AWS_ACCESS_KEY` | AWS Access Key ID | Crítica |
| `AWS_SECRET_KEY` | AWS Secret Access Key | Crítica |
| `GITHUB_TOKEN` | Token do GitHub (ghp_, gho_, ghu_, ghs_, ghr_) | Crítica |
| `GOOGLE_API_KEY` | Google API Key | Crítica |
| `GENERIC_PASSWORD` | Senha hardcoded (password, passwd, pwd, senha) | Alta |
| `PRIVATE_KEY` | Chave privada (RSA, EC, DSA, OpenSSH, PGP) | Crítica |
| `JWT_TOKEN` | Token JWT | Alta |
| `CONNECTION_STRING` | String de conexão com credenciais (MongoDB, PostgreSQL, MySQL, Redis) | Crítica |
 
### Detecção de PII (8 regras)
 
| Regra | O que detecta | Severidade |
|---|---|---|
| `BR_CPF` | CPF no formato 000.000.000-00 | Crítica |
| `BR_CNPJ` | CNPJ no formato 00.000.000/0000-00 | Média |
| `EMAIL_ADDRESS` | E-mail pessoal (ignora example.com e test.com) | Alta |
| `BR_PHONE` | Telefone brasileiro, com ou sem DDD e +55 | Média |
| `BR_RG` | RG (Registro Geral) | Crítica |
| `BR_CEP` | CEP no formato 00000-000 | Baixa |
| `CREDIT_CARD` | Número de cartão de crédito (13 a 16 dígitos) | Crítica |
| `FULL_NAME_HINT` | Possível nome pessoal em variável de dados | Média |
 
### Mapeamento normativo automático
 
Cada finding carrega o artigo da LGPD e o controle da ISO 27001 correspondentes:
 
| Tipo de achado | Artigo LGPD | Controle ISO 27001 |
|---|---|---|
| Secrets e credenciais | Art. 46 — Medidas de segurança | A.8.5 — Autenticação segura |
| Chave privada e cartão de crédito | Art. 46 / Art. 11 | A.8.24 — Criptografia |
| CPF e RG | Art. 11 — Dados sensíveis | A.8.10 — Supressão de dados |
| CNPJ, telefone e CEP | Art. 7 — Tratamento de dados | A.8.10 — Supressão de dados |
| E-mail e nome | Art. 5 — Direitos do titular | A.8.10 — Supressão de dados |
 
### Mascaramento de dados sensíveis
 
Todo texto capturado é mascarado antes de aparecer no relatório. Um CPF `123.456.789-00` aparece como `12***********00`. O relatório pode ser compartilhado sem vazar o dado que ele mesmo encontrou.
 
### Formatos de saída
 
- **Tabela** (`--format table`) — visual colorido por severidade no terminal, com arquivo, linha, tipo, regra, descrição, artigo LGPD e recomendação
- **JSON** (`--format json`) — relatório estruturado, com opção de salvar em arquivo
- **Resumo** (`--format summary`) — painel compacto com contagem por severidade
 
### Filtro por severidade
 
`--severity` permite exibir apenas findings a partir de um nível mínimo: `critical`, `high`, `medium`, `low` ou `info`.
 
### Exit code para CI
 
O comando retorna `1` quando encontra qualquer finding e `0` quando o código está limpo. Isso permite bloquear pipeline automaticamente:
 
```yaml
- name: PII Guard
  run: pii-guard scan . --severity high
```
 
## Cobertura de arquivos
 
O scanner analisa 14 extensões:
 
```text
.py  .js  .ts  .java  .go  .rb  .php  .env  .yaml  .yml  .json  .toml  .cfg  .ini  .sql
```
 
Diretórios ignorados automaticamente: `.venv`, `venv`, `__pycache__`, `.git`, `node_modules`, `.env`, `dist`, `build`, `.tox`, `.pytest_cache`.
 
> **Limitação atual:** o detector de PII roda apenas em arquivos `.py`. O detector de secrets roda em todas as extensões suportadas. Ampliar o detector de PII para as demais linguagens está no roadmap.
 
## Instalação
 
Requisitos: Python 3.11 ou superior.
 
```bash
git clone https://github.com/Berguy/pii-guard.git
cd pii-guard
 
python -m venv .venv
 
# Windows (Git Bash)
source .venv/Scripts/activate
# Linux / macOS
# source .venv/bin/activate
 
pip install -e .
```
 
## Uso
 
### Escanear um diretório
 
```bash
pii-guard scan .
```
 
### Escanear um arquivo específico
 
```bash
pii-guard scan src/config.py
```
 
### Gerar relatório JSON
 
```bash
pii-guard scan . --format json --output relatorio.json
```
 
### Mostrar apenas achados críticos e altos
 
```bash
pii-guard scan . --severity high
```
 
### Ver apenas o resumo
 
```bash
pii-guard scan . --format summary
```
 
### Opções disponíveis
 
| Opção | Atalho | Valores | Padrão |
|---|---|---|---|
| `--format` | `-f` | `table`, `json`, `summary` | `table` |
| `--output` | `-o` | caminho do arquivo | nenhum |
| `--severity` | `-s` | `critical`, `high`, `medium`, `low`, `info` | nenhum |
 
## Exemplo de saída
 
```text
┌─────────────────────────────────────────────┐
│            pii-guard — Resumo               │
│                                             │
│ Caminho: .                                  │
│ Arquivos escaneados: 42                     │
│ Total de findings: 3                        │
│ Critical: 2  High: 1  Medium: 0  Low: 0     │
└─────────────────────────────────────────────┘
 
        Findings Encontrados
┌──────────────┬───────┬────────────┬────────┬──────────────────┬─────────────────────────┬────────────────────────────┬──────────────────────────────┐
│ Arquivo      │ Linha │ Severidade │ Tipo   │ Regra            │ Descrição               │ LGPD                       │ Recomendação                 │
├──────────────┼───────┼────────────┼────────┼──────────────────┼─────────────────────────┼────────────────────────────┼──────────────────────────────┤
│ config.py    │ 12    │ CRITICAL   │ secret │ AWS_ACCESS_KEY   │ AWS Access Key ID       │ Art. 46 - Medidas de       │ Mova a chave para variável   │
│              │       │            │        │                  │ exposta no código       │ segurança                  │ de ambiente ou AWS IAM Role  │
├──────────────┼───────┼────────────┼────────┼──────────────────┼─────────────────────────┼────────────────────────────┼──────────────────────────────┤
│ clientes.py  │ 47    │ CRITICAL   │ pii    │ BR_CPF           │ CPF exposto no código   │ Art. 11 - Dados sensíveis  │ Remova o CPF do código e     │
│              │       │            │        │                  │                         │ e identificação pessoal    │ use pseudonimização          │
└──────────────┴───────┴────────────┴────────┴──────────────────┴─────────────────────────┴────────────────────────────┴──────────────────────────────┘
```
 
## Estrutura do projeto
 
```text
src/pii_guard/
├── cli.py              # interface de linha de comando (Click + Rich)
├── scanner.py          # orquestração dos detectores e varredura de diretórios
├── models.py           # Finding, ScanResult, Severity, FindingType (Pydantic)
└── detectors/
    ├── secrets.py      # 8 regras de detecção de credenciais
    └── pii.py          # 8 regras de detecção de dados pessoais
```
 
## Roadmap
 
| Etapa | Escopo | Status |
|---|---|---|
| Detecção de secrets | 8 regras com mapeamento LGPD/ISO | Concluída |
| Detecção de PII | 8 regras com mapeamento LGPD/ISO | Concluída |
| CLI com 3 formatos de saída | table, json, summary | Concluída |
| Filtro por severidade e exit code | Integração com CI | Concluída |
| Detector de PII em outras linguagens | Ampliar de `.py` para todas as extensões suportadas | Planejada |
| Detecção de PII em arquivos de configuração | `.env`, `.yaml`, `.json` | Planejada |
| Baseline de exceções | Arquivo de supressão para falsos positivos | Planejada |
| Action de GitHub Marketplace | Uso direto em pipeline sem instalação | Planejada |
 
## Contribuindo
 
Contribuições são bem-vindas. Para mudanças relevantes, abra uma issue descrevendo o problema ou a proposta antes de enviar um pull request.
 
```bash
git checkout -b feature/nome-da-feature
git commit -m "feat: descrição da mudança"
```
 
## Licença
 
Distribuído sob a licença **MIT**. Consulte o arquivo [LICENSE](LICENSE) para os termos completos.
 
## Autor
 
**Berguy Silva** — Engenheiro de software, pós-graduado em Computação Forense e Perícia Digital e em Gestão de Projetos.
 
- LinkedIn: https://www.linkedin.com/in/BerguySilva
- GitHub: https://github.com/Berguy
- Email: contato@berguysilva.com.br
 

