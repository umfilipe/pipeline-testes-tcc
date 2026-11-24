"""Constantes usadas em todo o pipeline."""

# Tempo máximo (em segundos) para go build, go test, gosec e Semgrep.
# Alguns repositórios grandes demoram para compilar com -race, por isso o valor é alto.
TIMEOUT_TESTES = 1800

# Tempo máximo (em segundos) para a PoC do benchmark (/workspace/fix-run.sh).
TIMEOUT_POC = 600

# Proxy de módulos Go usado só na preparação do container (a única etapa com rede).
# Algumas imagens vêm configuradas com proxies chineses (goproxy.cn), lentos ou
# inacessíveis daqui; o proxy oficial do Go resolve as mesmas versões.
GOPROXY_PREPARACAO = "https://proxy.golang.org,direct"

# Configuração padrão do Semgrep: o pacote de regras "p/golang" do registro online.
# Para resultados reproduzíveis, prefira passar o arquivo local
# config/regras_semgrep_golang.yaml com --semgrep-config.
SEMGREP_CONFIG = "p/golang"

# Opções fixas de toda execução do Semgrep. --no-git-ignore é obrigatória: o
# código analisado é copiado para resultados/, que o .gitignore do projeto
# ignora; sem ela, o Semgrep pula todos os arquivos e não acha nada.
SEMGREP_OPCOES = ["--no-git-ignore", "--disable-version-check", "--metrics=off", "--json", "--quiet"]
