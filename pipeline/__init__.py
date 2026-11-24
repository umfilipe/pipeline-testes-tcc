"""Pipeline de avaliação de patches em Go sobre o PatchEval-Verified.

Para cada caso (CVE):
  1. sobe o container do CVE, baixa as dependências Go (única etapa com rede) e
     desconecta o container da rede;
  2. versão vulnerável: testes unitários escolhidos pelo benchmark
     (/workspace/unit_test.sh, com -race -json), gosec e Semgrep (linha de base);
  3. checa o patch com `git apply --check` (estrito) e aplica;
  4. versão corrigida: go build, testes, gosec e Semgrep;
  5. se o gosec ou o Semgrep acusar um achado novo, grava achados_novos.log
     (sem parar: o achado só impede o aprovado_automatico);
  6. roda a PoC do benchmark (/workspace/fix-run.sh);
  7. compara as duas versões: testes quebrados e corridas novas.

Organização do pacote:
  config.py      -> constantes (timeouts, proxy da preparação, configuração do Semgrep)
  ambiente.py    -> preparação e isolamento do container, leitura do unit_test.sh
  conteiner.py   -> execução de comandos no host e dentro do container Docker
  testes_go.py   -> leitura da saída de `go test -json` e comparação entre versões
  sast.py        -> execução do gosec e do Semgrep e comparação dos achados
  patches.py     -> montagem, filtragem e download dos patches
  avaliacao.py   -> avaliação completa de um caso (as etapas 1 a 7 acima)
  relatorio.py   -> escrita do resumo.csv
  __main__.py    -> interface de linha de comando (python3 -m pipeline ...)

Uso (a partir da raiz do projeto):
  python3 -m pipeline --casos dados/piloto.json --oficial --saida resultados/oficial \\
      --semgrep-config config/regras_semgrep_golang.yaml
  python3 -m pipeline --casos dados/piloto.json --patches patches/patches_claude-opus.json \\
      --saida resultados/claude-opus --semgrep-config config/regras_semgrep_golang.yaml
"""
