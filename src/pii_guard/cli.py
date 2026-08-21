"""
CLI do pii-guard.

Interface de linha de comando para executar o scanner
de secrets e PII com saída formatada e relatório JSON.
"""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.console import Group

from pii_guard.scanner import Scanner

console = Console()

@click.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "-f", type=click.Choice(["table", "json", "summary"]), default="table", help="Formato de saída")
@click.option("--output", "-o", type=click.Path(), default=None, help="Arquivo para salvar o relatório JSON")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]), default=None, help="Filtrar por severidade mínima")
def main(target: str, format: str, output: str | None, severity: str | None) -> None:
    """Scanner de secrets e PII para conformidade com LGPD.

    TARGET é o caminho do arquivo ou diretório a ser escaneado.
    """
    try:
        scanner = Scanner(target)
        result = scanner.scan()
    except FileNotFoundError as e:
        console.print(f"[red]Erro:[/red] {e}")
        sys.exit(1)

    # Filtrar por severidade se solicitado
    if severity:
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_level = severity_order[severity]
        result.findings = [f for f in result.findings if severity_order[f.severity.value] >= min_level]

    # Exibir resultado
    if format == "json":
        output_json = result.model_dump_json(indent=2)
        if output:
            Path(output).write_text(output_json, encoding="utf-8")
            console.print(f"[green]Relatório salvo em:[/green] {output}")
        else:
            console.print(output_json)

    elif format == "summary":
        _print_summary(result)

    else:
        _print_table(result)

    # Exit code baseado em findings
    if result.total_findings > 0:
        sys.exit(1)
    sys.exit(0)

def _print_summary(result) -> None:
    """Imprime um resumo compacto do scan."""
    panel_content = Group(
        f"[bold]Caminho:[/bold] {result.target_path}",
        f"[bold]Arquivos escaneados:[/bold] {result.files_scanned}",
        f"[bold]Total de findings:[/bold] {result.total_findings}",
        f"[red]Critical:[/red] {result.critical_count}  "
        f"[yellow]High:[/yellow] {result.high_count}  "
        f"[blue]Medium:[/blue] {result.medium_count}  "
        f"[green]Low:[/green] {result.low_count}",
    )
    console.print(Panel(panel_content, title="[bold]pii-guard — Resumo[/bold]", border_style="cyan"))

def _print_table(result) -> None:
    """Imprime os findings em uma tabela rica."""
    _print_summary(result)

    if not result.findings:
        console.print("\n[green]✓ Nenhum problema encontrado![/green]")
        return

    table = Table(title="Findings Encontrados", show_lines=True)
    table.add_column("Arquivo", style="cyan", no_wrap=True)
    table.add_column("Linha", justify="right", style="white")
    table.add_column("Severidade", style="bold")
    table.add_column("Tipo")
    table.add_column("Regra", style="yellow")
    table.add_column("Descrição")
    table.add_column("LGPD")
    table.add_column("Recomendação", style="green")

    severity_colors = {
        "critical": "red",
        "high": "yellow",
        "medium": "blue",
        "low": "green",
        "info": "white",
    }

    for finding in result.findings:
        color = severity_colors.get(finding.severity.value, "white")
        table.add_row(
            Path(finding.file_path).name,
            str(finding.line_number),
            f"[{color}]{finding.severity.value.upper()}[/{color}]",
            finding.finding_type.value,
            finding.rule_id,
            finding.description,
            finding.lgpd_article,
            finding.recommendation,
        )

    console.print(table)

if __name__ == "__main__":
    main()