"""Leitura dos resultados de `go test -json` e comparação entre as versões."""
import json


def parse_go_test_json(texto):
    """Extrai o resultado final de cada teste da saída de `go test -json`.

    Devolve um dicionário {"pacote::Teste": "pass" | "fail" | "skip"}.
    Linhas que não são JSON (mensagens do compilador, avisos do race detector
    impressos fora do fluxo JSON etc.) são ignoradas.
    """
    res = {}
    for linha in texto.splitlines():
        linha = linha.strip()
        # cada evento do go test -json é um objeto JSON em uma linha
        if not linha.startswith("{"):
            continue
        try:
            ev = json.loads(linha)
        except json.JSONDecodeError:
            continue
        # só interessam os eventos finais de um teste (não os de pacote, sem "Test")
        if ev.get("Test") and ev.get("Action") in ("pass", "fail", "skip"):
            res[f'{ev.get("Package")}::{ev["Test"]}'] = ev["Action"]
    return res


def contar_corridas(texto):
    """Conta quantas condições de corrida o race detector (-race) relatou."""
    return texto.count("WARNING: DATA RACE")


def comparar_testes(base, depois):
    """Compara os testes da versão vulnerável (`base`) com os da versão corrigida.

    Devolve duas listas ordenadas:
      - quebrados: passavam na versão vulnerável e não passam mais após o patch
        (falharam, foram pulados ou nem chegaram a rodar);
      - ja_falhavam: já falhavam antes do patch (não contam como regressão).
    """
    quebrados = sorted(t for t, r in base.items() if r == "pass" and depois.get(t) != "pass")
    ja_falhavam = sorted(t for t, r in base.items() if r == "fail")
    return quebrados, ja_falhavam
