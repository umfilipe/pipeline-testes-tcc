#!/usr/bin/env python3
"""Gera um prompt por caso, no estilo do PatchEval, e os arquivos de resposta vazios.

Uso (a partir da raiz do projeto):
    python3 scripts/gerar_prompts.py dados/piloto.json prompts/ --modelos claude-opus gemini-neon

Cria:
    prompts/<CVE>.txt              o prompt de cada caso
    respostas/<modelo>/<CVE>.md    um arquivo vazio por caso e por modelo de --modelos

Para cada caso, envie o prompt ao modelo (via Claude Code ou Antigravity CLI,
numa conversa nova) e cole o conteúdo do resposta.txt que o modelo criar (seção
"Entrega" do prompt) no respostas/<modelo>/<CVE>.md correspondente. Arquivos de resposta que já existem não são tocados, então
rodar o script de novo não apaga respostas já coladas. Depois rode
scripts/montar_patches.py para gerar o JSON que o pipeline (pasta pipeline/) lê.
"""
import argparse
import json
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent

MODELO_PROMPT = """Você é um engenheiro de segurança especializado em Go. Sua tarefa é \
corrigir uma vulnerabilidade de segurança em um projeto de código aberto real.

## Vulnerabilidade
{descricao}

## Código vulnerável
Repositório: {repo}
A vulnerabilidade está na(s) função(ões) abaixo.

{funcoes}

## Instruções
1. Pense passo a passo sobre a causa raiz da vulnerabilidade e como corrigi-la \
sem alterar o comportamento esperado do programa.
2. Reescreva a(s) função(ões) vulnerável(is) para corrigir a vulnerabilidade.
3. Mantenha o mesmo nome, receptor e assinatura da função.
4. Se a correção precisar de uma nova função auxiliar, escreva-a logo após a função \
corrigida, no mesmo bloco de código.
5. Não adicione novos imports e não altere outras partes do arquivo.
6. Responda em português.

## Formato da resposta
Retorne {n_blocos} bloco(s) de código Go, na mesma ordem das funções vulneráveis \
acima, cada um com a função corrigida completa (mais eventuais funções auxiliares novas):

```go
// função corrigida aqui
```

## Entrega
Crie um arquivo de texto chamado `resposta.txt` com a sua resposta completa: a \
análise e o(s) bloco(s) de código Go, mantendo as marcações ```go de cada bloco.
"""


def montar(caso):
    # O prompt não traz o identificador do CVE nem as CWEs: com eles, o modelo
    # poderia reconhecer a vulnerabilidade (ou lembrar a correção publicada) em
    # vez de analisar o código. Fica só a descrição da falha.
    funcoes = "\n\n".join(
        f"### Função {i} — arquivo `{f['file_path']}`, linhas {f['start_line']}-{f['end_line']}\n"
        f"```go\n{f['snippet'].rstrip()}\n```"
        for i, f in enumerate(caso["vul_func"], 1))
    return MODELO_PROMPT.format(descricao=caso["cve_description"].strip(),
                                repo=caso["repo"], funcoes=funcoes,
                                n_blocos=len(caso["vul_func"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("casos", help="JSON com os casos (ex.: dados/piloto.json)")
    ap.add_argument("pasta", help="pasta onde gravar os prompts (ex.: prompts/)")
    ap.add_argument("--modelos", nargs="+", default=[],
                    help="nomes dos modelos; cria respostas/<modelo>/<CVE>.md vazio para cada um")
    args = ap.parse_args()

    pasta = Path(args.pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    casos = json.load(open(args.casos, encoding="utf-8"))
    for caso in casos:
        (pasta / f"{caso['cve_id']}.txt").write_text(montar(caso), encoding="utf-8")
    print(f"{len(casos)} prompts em {pasta}/")

    for modelo in args.modelos:
        destino = RAIZ / "respostas" / modelo
        destino.mkdir(parents=True, exist_ok=True)
        novos = 0
        for caso in casos:
            arq = destino / f"{caso['cve_id']}.md"
            # nunca sobrescreve: o arquivo pode já ter uma resposta colada
            if not arq.exists():
                arq.touch()
                novos += 1
        print(f"respostas/{modelo}/: {novos} arquivos vazios criados, "
              f"{len(casos) - novos} já existiam")


if __name__ == "__main__":
    main()
