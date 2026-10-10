# Guia de Uso — RustScan Automator

Ferramenta de **reconhecimento** (recon) que orquestra o
[RustScan](https://github.com/RustScan/RustScan) no lugar do nmap, inspirada nos
fluxos do [nmapAutomator](https://github.com/21y4d/nmapAutomator).

> Escopo: **somente reconhecimento**. Exploração e ferramentas de terceiros
> (nikto, dirb, gobuster, ffuf, wpscan, metasploit etc.) estão **fora do escopo**
> e são bloqueadas por uma allowlist de argumentos do nmap.

---

## 1. Pré-requisitos

| Dependência | Para quê | Como instalar |
|-------------|----------|---------------|
| Rust / Cargo | Compilar a ferramenta | https://rustup.rs |
| RustScan ≥ 2.x | Motor de varredura | https://github.com/RustScan/RustScan/releases · ou `cargo install rustscan` |
| nmap ≥ 7.x | Apenas para os modos `service`, `vuln` e `full` | `sudo apt install nmap` (Debian/Ubuntu) · `brew install nmap` (macOS) |
| privilégios de root | Apenas para o modo `udp` | `sudo` |

Confirme as versões:

```bash
cargo --version
rustscan --version
nmap --version
```

---

## 2. Compilar

```bash
git clone https://github.com/orionhack99/rustscan-automator.git
cd rustscan-automator
cargo build --release
```

O binário fica em `./target/release/rustscan-automator`.

Dica: para chamá-lo de qualquer lugar, copie para o `PATH`:

```bash
cp target/release/rustscan-automator ~/.local/bin/
```

---

## 3. Passo a passo de uso

Sintaxe geral:

```bash
rustscan-automator -H <ALVO> -t <MODO> [opções]
```

Onde `<ALVO>` é um **IP**, um **hostname** ou um **CIDR** (ex.: `10.0.0.0/24`).

### 3.1 Descobrir portas abertas (modo `port`)

O primeiro passo de qualquer recon. Varre a faixa de portas e mostra as abertas.

```bash
rustscan-automator -H 10.0.0.5 -t port
```

Limitar a uma faixa de portas (mais rápido):

```bash
rustscan-automator -H 10.0.0.5 -t port --ports 1-1000
```

### 3.2 Identificar serviços e versões (modo `service`)

Anota as portas abertas com serviço e versão (usa o handoff do RustScan para o
nmap com `-sV -sC`, apenas recon).

```bash
rustscan-automator -H 10.0.0.5 -t service --ports 22,80,443
```

Se você não informar `--ports`, ele faz uma descoberta rápida antes.

### 3.3 Verificações de vulnerabilidade (modo `vuln`)

Roda a categoria `vuln` dos scripts NSE do nmap (somente recon, sem exploração).

```bash
rustscan-automator -H 10.0.0.5 -t vuln --ports 22,80,443
```

### 3.4 Descoberta de hosts vivos (modo `network`)

Descobre hosts ativos em uma faixa usando sondagens TCP nas portas comuns
(o RustScan não tem modo "ping" puro, então usamos sondagens de conexão).

```bash
rustscan-automator -H 10.0.0.0/24 -t network
```

### 3.5 Portas UDP (modo `udp`)

Precisa de privilégios elevados (sockets raw).

```bash
sudo rustscan-automator -H 10.0.0.5 -t udp --ports 53,123,161
```

### 3.6 Fluxo completo (modo `full` ou `all`)

Faz a varredura de todas as portas, depois recon de serviço e de vulnerabilidade
nas portas novas. Falhas de uma fase não abortam o restante.

```bash
rustscan-automator -H 10.0.0.5 -t full
```

### 3.7 Sugestões internas (modo `recon`)

Faz uma varredura rápida e imprime sugestões de próximos passos **sem chamar
nenhuma ferramenta externa**.

```bash
rustscan-automator -H 10.0.0.5 -t recon
```

### 3.8 Opções úteis

```bash
-H, --host <ALVO>            IP, hostname ou CIDR
-t, --type <MODO>            network | port | service | vuln | udp | full | all | recon
-o, --output <DIR>           diretório de saída (padrão: ./rustscan-automator-output)
-d, --dns <SERVIDOR>         resolver de DNS
-s, --static-rustscan <PATH> caminho explícito do binário RustScan
    --ports <LISTA>          portas (ex.: 22,80,443 ou 1-1000)
    --ports-file <ARQ>       arquivo com uma porta/faixa por linha
    --batch-size <N>         concorrência do RustScan
    --timeout <MS>           timeout por porta (ms)
    --yes                    modo não interativo (sem prompts)
    --no-color               desativa cores (também respeita a variável NO_COLOR)
-h, --help                   ajuda
-V, --version                versão
```

Exemplos completos:

```bash
# Salvar em pasta específica, sem prompts
rustscan-automator -H 10.10.10.5 -t port -o ./resultados --yes

# Lista de portas vinda de arquivo
rustscan-automator -H scanme.exemplo.com -t service --ports-file portas.txt

# Usando um RustScan específico
rustscan-automator -H 10.10.10.5 -t port -s /opt/rustscan/rustscan
```

---

## 4. Onde ficam os resultados

Tudo é gravado em `<saída>/<alvo>/`:

```
<saída>/<alvo>/
├── <alvo>_<modo>_<timestamp>.txt     # achados legíveis
├── <alvo>_<modo>_<timestamp>.json    # achados estruturados
├── <alvo>_summary_<timestamp>.txt    # resumo do run
├── <alvo>_summary_<timestamp>.json   # resumo estruturado
└── <alvo>_session_<timestamp>.log    # log completo da sessão
```

Arquivos existentes **nunca são sobrescritos**: em caso de colisão de nome, é
adicionado um sufixo `-1`, `-2`, etc.

---

## 5. Códigos de saída

| Código | Significado |
|--------|-------------|
| `0` | Sucesso |
| `1` | Falha em tempo de execução |
| `2` | Entrada inválida (alvo/modo/opções) |
| `3` | Dependência ausente (RustScan/nmap) |
| `4` | Privilégio necessário (ex.: `udp` sem root) |

---

## 6. Observações de escopo

- A ferramenta **só faz reconhecimento**; não explora nem usa ferramentas de
  terceiros.
- O handoff para o nmap é restrito: `-sV -sC -Pn` e `--script {default,vuln,safe,discovery}`.
  Qualquer argumento fora da allowlist é rejeitado.
- O modo `network` usa sondagens TCP em portas comuns (limitação do RustScan,
  que não possui ping ICMP puro).

---

## 7. Desenvolvimento

```bash
cargo test        # testes herméticos: nunca tocam a rede real
cargo clippy -- -D warnings
cargo fmt --check
```

Os testes usam um `CommandRunner` falso, então o `cargo test` não dispara
varreduras reais.

---

## 8. Uso ético e legal

Use **apenas** em alvos para os quais você tem autorização explícita. Varreduras
não autorizadas podem ser ilegais. Alvos públicos de teste: `scanme.nmap.org`,
`scanme.sh`.
