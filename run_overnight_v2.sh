#!/usr/bin/env bash
# =============================================================================
#  run_overnight_v2.sh  --  Orquestrador NOTURNO dos runs do dataset NIDS
#  Versao 2: incorpora as licoes da depuracao (orfaos NB2, overlap fallback).
# =============================================================================
#
#  O QUE MUDOU DA v1 (e POR QUE)
#  -----------------------------
#  A v1 falhou por dois motivos que descobrimos rodando:
#    1. PROCESSOS ORFAOS NA NB2: cada run deixava ~13 python.exe vivos na NB2,
#       que saturavam a maquina e faziam o passo ready_benign FALHAR. => Agora o
#       script MATA os orfaos da NB2 antes de cada run.
#    2. LAB NAO-ASSENTADO -> OVERLAP FALLBACK: quando o lab roda "torto" (logo
#       apos matar orfaos, timing desalinhado), os ataques rodam curtos, a
#       sobreposicao temporal captura<->ataque cai, e >10% dos fluxos usam o
#       metodo de fallback -> o run vira DIAGNOSTICO (official=False), que conta
#       como FALHA mesmo passando todos os gates. => Agora o script (a) da FOLGA
#       para o lab assentar antes de cada run, e (b) VERIFICA a taxa de fallback
#       e o diagnostic_reasons apos cada run, nao so o PASS/FAIL.
#
#  CRITERIO DE SUCESSO (mais rigoroso que a v1)
#  --------------------------------------------
#  Um run so conta como PASS se TUDO isto for verdade:
#    - overall == PASS
#    - official == True           (NAO diagnostico)
#    - diagnostic_reasons == []   (nenhum motivo de rebaixamento)
#  Se passar os gates mas sair DIAGNOSTICO (ex.: overlap fallback > 10%), conta
#  como FALHA -> re-roda 1x limpando TUDO antes (orfaos NB2 + residuos).
#
#  POLITICA DE FALHA (decisao do usuario)
#  --------------------------------------
#    - Falhou -> tenta 1x de novo (limpando tudo antes). Se falhar de novo, PULA.
#    - 2 runs CONSECUTIVOS falhando pela MESMA causa -> PARA (algo quebrou).
#
#  RUNS
#  ----
#    Default: 2 3 4 5 6  (preserva run0 e run1, ja validados/oficiais).
#
#  USO
#  ---
#    chmod +x run_overnight_v2.sh
#    screen -S overnight ./run_overnight_v2.sh        # recomendado
#    ./run_overnight_v2.sh 2 3                          # runs especificos
#
#  De manha:  cat ~/ProjetoDataset/overnight_logs/SUMMARY.txt
# =============================================================================

set -u

# ------------------------------------------------------------------ CONFIG
PROJ="$HOME/ProjetoDataset"
SRC="/opt/nids/src"
BASE="/mnt/nids-captures"
MANIFEST="$PROJ/lab/campaign.official.json"
KEY="${LAB_SSH_KEY:-$HOME/.ssh/id_lab}"

NB1="${NB1_HOST:-user@10.10.10.11}"      # vitima (Caddy + WordPress)
NB2="${NB2_HOST:-user@10.10.10.20}"         # gerador benigno (Windows) -- onde ficam os orfaos
NB3="${NB3_HOST:-user@10.10.10.30}"    # atacante

RUNS="${RUNS:-${*:-2 3 4 5 6}}"
VHOSTS="blog shop docs wiki forum api news store"
MAX_TRIES=2

# Folga (segundos) para o lab assentar apos garantir Caddy, ANTES de disparar o
# run. Foi a ausencia disto que causou o overlap fallback no run0.
SETTLE_SECONDS=25

# teto de fallback do manifesto (so para reportar; o label_flows aplica sozinho)
FALLBACK_CEIL_PCT=10

LOGDIR="$PROJ/overnight_logs"
mkdir -p "$LOGDIR"
SUMMARY="$LOGDIR/SUMMARY.txt"
MAINLOG="$LOGDIR/overnight_$(date +%Y%m%dT%H%M%SZ).log"

# ------------------------------------------------------------------ LOG
# CRITICO: log/summary escrevem em stderr (>&2), NAO em stdout. Varias funcoes
# retornam seu resultado via stdout ($(funcao)); se o log fosse para stdout, ele
# vazaria para dentro dessas variaveis. (Foi o bug da v1.)
log()     { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$MAINLOG" >&2; }
summary() { echo "$*" | tee -a "$SUMMARY" >&2; }

# ------------------------------------------------------------------ NB2 HYGIENE
kill_nb2_orphans() {
    # Mata os python.exe orfaos na NB2 (a causa do ready_benign falhar na v1).
    # Idempotente: se nao houver nenhum, taskkill so avisa e seguimos.
    log "  [nb2] matando processos python.exe orfaos na NB2..."
    ssh -i "$KEY" -o ConnectTimeout=8 "$NB2" 'taskkill /F /IM python.exe' >>"$MAINLOG" 2>&1
    sleep 2
    # confirmar que ficou limpa
    local left
    left=$(ssh -i "$KEY" -o ConnectTimeout=8 "$NB2" 'tasklist | findstr python' 2>/dev/null | wc -l)
    if [ "${left:-0}" -eq 0 ]; then
        log "  [nb2] NB2 limpa (nenhum python.exe)."
        return 0
    fi
    log "  [nb2] AVISO: ainda ha $left python.exe na NB2 apos taskkill."
    # nao bloqueia -- as vezes um processo demora a morrer; damos mais um tempo
    sleep 3
    return 0
}

# ------------------------------------------------------------------ ENV CHECKS
ssh_ok() {
    local node="$1"
    ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=8 "$node" hostname >/dev/null 2>&1
}

caddy_up_and_healthy() {
    log "  [env] garantindo Caddy + 8 vhosts..."
    ssh -i "$KEY" -o ConnectTimeout=8 "$NB1" \
        'docker ps --format "{{.Names}}" | grep -q caddy || (cd ~/ProjetoDataset/lab && docker compose up -d caddy)' \
        >>"$MAINLOG" 2>&1
    sleep 12
    local attempt fails
    for attempt in 1 2; do
        fails=0
        for h in $VHOSTS; do
            code=$(curl -sk -m5 -o /dev/null -w "%{http_code}" "https://$h.lab/" 2>/dev/null)
            [ "$code" != "200" ] && { log "    [env] $h.lab -> $code"; fails=$((fails+1)); }
        done
        [ "$fails" -eq 0 ] && { log "  [env] Caddy OK (8 vhosts em 200)."; return 0; }
        if [ "$attempt" -eq 1 ]; then
            log "  [env] $fails vhost(s) fora; subindo Caddy de novo..."
            ssh -i "$KEY" -o ConnectTimeout=8 "$NB1" 'cd ~/ProjetoDataset/lab && docker compose up -d caddy' >>"$MAINLOG" 2>&1
            sleep 15
        fi
    done
    log "  [env] FALHA: $fails vhost(s) != 200."
    return 1
}

manifest_synced() {
    local want nb1h nb3h
    want=$(sha256sum "$MANIFEST" 2>/dev/null | cut -d' ' -f1)
    [ -z "$want" ] && { log "  [env] ERRO: hash local do manifesto ilegivel."; return 1; }
    nb1h=$(ssh -i "$KEY" -o ConnectTimeout=8 "$NB1" "sha256sum ~/ProjetoDataset/lab/campaign.official.json 2>/dev/null" | cut -d' ' -f1)
    nb3h=$(ssh -i "$KEY" -o ConnectTimeout=8 "$NB3" "sha256sum ~/ProjetoDataset/lab/campaign.official.json 2>/dev/null" | cut -d' ' -f1)
    if [ "$nb1h" = "$want" ] && [ "$nb3h" = "$want" ]; then
        log "  [env] manifesto identico nos 3 nos (${want:0:12}...)."
        return 0
    fi
    log "  [env] hash divergente; re-sincronizando (NB4=${want:0:12} NB1=${nb1h:0:12} NB3=${nb3h:0:12})..."
    [ "$nb1h" != "$want" ] && scp -i "$KEY" "$MANIFEST" "$NB1:~/ProjetoDataset/lab/campaign.official.json" >>"$MAINLOG" 2>&1
    [ "$nb3h" != "$want" ] && scp -i "$KEY" "$MANIFEST" "$NB3:~/ProjetoDataset/lab/campaign.official.json" >>"$MAINLOG" 2>&1
    nb1h=$(ssh -i "$KEY" -o ConnectTimeout=8 "$NB1" "sha256sum ~/ProjetoDataset/lab/campaign.official.json 2>/dev/null" | cut -d' ' -f1)
    nb3h=$(ssh -i "$KEY" -o ConnectTimeout=8 "$NB3" "sha256sum ~/ProjetoDataset/lab/campaign.official.json 2>/dev/null" | cut -d' ' -f1)
    [ "$nb1h" = "$want" ] && [ "$nb3h" = "$want" ] && { log "  [env] manifesto re-sincronizado."; return 0; }
    log "  [env] FALHA: manifesto ainda divergente."
    return 1
}

airgap_ok() {
    local wifi route
    wifi=$(nmcli -t -f WIFI radio 2>/dev/null)
    route=$(ip route show default 2>/dev/null)
    if [ "$wifi" = "disabled" ] && [ -z "$route" ]; then
        log "  [env] ar-gap OK."; return 0
    fi
    log "  [env] AVISO: ar-gap suspeito (WiFi=$wifi rota='$route')."
    return 0
}

prepare_environment() {
    # Ordem importa: SSH -> NB2 limpa -> Caddy -> manifesto -> ar-gap -> ASSENTAR.
    # Retorna "ok" (stdout) ou uma causa curta de falha.
    if ! ssh_ok "$NB1"; then echo "ssh_nb1"; return; fi
    if ! ssh_ok "$NB2"; then echo "ssh_nb2"; return; fi
    if ! ssh_ok "$NB3"; then echo "ssh_nb3"; return; fi
    kill_nb2_orphans          # <<< licao 1: NB2 sem orfaos
    if ! caddy_up_and_healthy; then echo "caddy"; return; fi
    if ! manifest_synced; then echo "manifest"; return; fi
    airgap_ok
    # <<< licao 2: dar FOLGA para o lab assentar antes de disparar (evita o
    # overlap fallback que rebaixou o run0 a diagnostico).
    log "  [env] deixando o lab assentar por ${SETTLE_SECONDS}s..."
    sleep "$SETTLE_SECONDS"
    echo "ok"
}

# ------------------------------------------------------------------ VERIFICACAO PASS
verify_run() {
    # Verifica se o run e OFICIAL (nao so PASS): overall==PASS E official==True E
    # diagnostic_reasons==[]. Imprime o diagnostico em stderr (nao stdout) e
    # retorna 0 se OFICIAL, 1 caso contrario. Tambem reporta a taxa de fallback.
    local N="$1"
    python3 - "$N" <<'PY' 2> >(tee -a "$MAINLOG" >&2)
import json, sys, os
N = sys.argv[1]
def emit(m): print(m, file=sys.stderr)
base = f"/mnt/nids-captures/run{N}"
cs = f"{base}/run{N}_completion_status.json"
rs = f"{base}/run{N}_run_status.json"
if not os.path.exists(cs):
    emit(f"    [verify] run{N}: SEM completion_status (nao selou)")
    sys.exit(1)
try:
    d = json.load(open(cs))
except Exception as e:
    emit(f"    [verify] run{N}: completion_status ilegivel ({e})")
    sys.exit(1)
overall  = d.get("overall")
official = d.get("official")
# taxa de fallback e contagens, do run_status (se existir)
fb_pct = None; classes = None; diag = None
if os.path.exists(rs):
    try:
        s = json.load(open(rs))
        oa = s.get("overlap_accounting", {}) or {}
        fb = oa.get("duration_fallback_flows", 0); m = oa.get("matched_flows", 0)
        fb_pct = (100.0*fb/m) if m else 0.0
        classes = s.get("class_counts_split_ready")
        diag = s.get("diagnostic_reasons")
    except Exception:
        pass
sem = d.get("semantics", {})
states = {k:(v.get("state") if isinstance(v,dict) else v) for k,v in sem.items()}
emit(f"    [verify] run{N}: overall={overall} official={official} "
     f"fallback={fb_pct:.2f}%" if fb_pct is not None else
     f"    [verify] run{N}: overall={overall} official={official}")
if diag is not None:
    emit(f"    [verify] run{N}: diagnostic_reasons={diag}")
if classes is not None:
    emit(f"    [verify] run{N}: class_counts={json.dumps(classes, ensure_ascii=False)}")
emit(f"    [verify] run{N}: semantics={states}")
# criterio: OFICIAL = overall PASS + official True + sem diagnostic_reasons
ok = (overall == "PASS") and (official is True) and (not diag)
if not ok:
    if overall == "PASS" and official is not True:
        emit(f"    [verify] run{N}: >>> passou os gates mas saiu DIAGNOSTICO (nao oficial)")
sys.exit(0 if ok else 1)
PY
}

# ------------------------------------------------------------------ RUN DE 1 RUN
run_one() {
    local N="$1"
    local runlog="$LOGDIR/run${N}_$(date +%Y%m%dT%H%M%SZ).log"
    local try cause

    log "================ RUN $N -- inicio ================"

    for (( try=1; try<=MAX_TRIES; try++ )); do
        log "  [run$N] tentativa $try de $MAX_TRIES"

        # (a) PREPARAR ambiente (inclui matar orfaos NB2 + assentar o lab)
        cause=$(prepare_environment)
        if [ "$cause" != "ok" ]; then
            log "  [run$N] ambiente NAO pronto (causa: $cause)."
            LAST_CAUSE="$cause"
            continue
        fi

        # (b) LIMPAR TUDO do run: residuos + attempts (limpa antes de CADA tentativa)
        log "  [run$N] limpando residuos de run$N (dir + attempts)..."
        rm -rf "$BASE/run$N" "$BASE"/run${N}_attempt_* 2>/dev/null

        # (c) overwrite:true no config
        local ow
        ow=$(python3 -c "import json;print(json.load(open('$PROJ/run$N.json')).get('overwrite'))" 2>/dev/null)
        if [ "$ow" != "True" ]; then
            log "  [run$N] ligando overwrite no run$N.json..."
            python3 -c "import json;p='$PROJ/run$N.json';c=json.load(open(p));c['overwrite']=True;json.dump(c,open(p,'w'),indent=2)" 2>>"$MAINLOG"
        fi

        # (d) EXECUCAO REAL (~60 min). NAO rodamos --dry-run antes: ele nao valida
        #     label_flows/finalize (so registra intencao), e gastaria uma passada
        #     a toa. Vamos direto ao run real.
        log "  [run$N] execucao real (~60 min)... (log: $runlog)"
        python3 "$SRC/orchestrate_run.py" --config "$PROJ/run$N.json" >>"$runlog" 2>&1
        local rc=$?
        log "  [run$N] orchestrate retornou codigo $rc"

        # (e) VERIFICAR: oficial? (overall PASS + official True + sem diagnostico)
        if verify_run "$N"; then
            log "  [run$N] >>> PASS OFICIAL confirmado."
            summary "run$N: PASS oficial   (tentativa $try, $(date +'%Y-%m-%d %H:%M'))"
            log "================ RUN $N -- FIM (PASS oficial) ================"
            echo "pass"; return
        fi

        # falhou (ou saiu diagnostico) -> registrar motivo e, se for re-rodar,
        # a limpeza acontece no topo do proximo loop (letra b) + orfaos (letra a)
        log "  [run$N] NAO oficial nesta tentativa."
        # tentar extrair o motivo do FAIL (se selou com algum dominio FAIL)
        python3 - "$N" >>"$MAINLOG" 2>&1 <<'PY'
import json,sys,os
N=sys.argv[1]
p=f"/mnt/nids-captures/run{N}/run{N}_completion_status.json"
if os.path.exists(p):
    d=json.load(open(p))
    for k,v in d.get("semantics",{}).items():
        if isinstance(v,dict) and v.get("state")=="FAIL":
            det=v.get("detail",{})
            print(f"    [run{N}] FAIL em {k}: {det.get('problems') or det.get('problem') or det.get('reason')}")
PY
        LAST_CAUSE="run_fail"
    done

    summary "run$N: FALHOU  (apos $MAX_TRIES tentativas, $(date +'%Y-%m-%d %H:%M'))"
    log "================ RUN $N -- FIM (FALHOU) ================"
    echo "${LAST_CAUSE:-run_fail}"; return
}

# ------------------------------------------------------------------ MAIN
summary "==================================================================="
summary " CAMPANHA NOTURNA v2 -- inicio $(date +'%Y-%m-%d %H:%M:%S')"
summary " runs: $RUNS   (run0 e run1 preservados -- ja oficiais)"
summary " criterio: PASS + official:True + diagnostic_reasons:[]"
summary "==================================================================="
log "Log principal: $MAINLOG | Runs: $RUNS"

# validar configs antes de comecar (filtro anti-parasita + existencia)
log "Validando configs..."
for N in $RUNS; do
    if [ ! -f "$PROJ/run$N.json" ]; then
        log "FATAL: run$N.json nao existe."; summary "ABORTADO: run$N.json ausente."; exit 1
    fi
    hasfilter=$(python3 -c "import json;print('not host 10.10.10.4' in ' '.join(json.load(open('$PROJ/run$N.json')).get('capture_args',[])))" 2>/dev/null)
    if [ "$hasfilter" != "True" ]; then
        log "FATAL: run$N.json sem filtro anti-parasita."; summary "ABORTADO: run$N.json sem filtro."; exit 1
    fi
done
log "Configs OK (filtro anti-parasita presente em todos)."

PREV_CAUSE=""
CONSEC=0
for N in $RUNS; do
    result=$(run_one "$N")

    if [ "$result" = "pass" ]; then
        PREV_CAUSE=""; CONSEC=0
        continue
    fi

    if [ "$result" = "$PREV_CAUSE" ] && [ -n "$result" ]; then
        CONSEC=$((CONSEC+1))
    else
        CONSEC=1
    fi
    PREV_CAUSE="$result"

    if [ "$CONSEC" -ge 2 ]; then
        log "!!! 2 runs consecutivos falharam por '$result'. PARANDO (algo quebrou)."
        summary ""
        summary "PARADA DE SEGURANCA: 2 falhas consecutivas por '$result'."
        summary "Nao tentados: $(echo $RUNS | tr ' ' '\n' | sed -n "/^$N\$/,\$p" | tail -n +2 | tr '\n' ' ')"
        break
    fi
    log "run$N pulado (causa: $result). Proximo."
done

# ------------------------------------------------------------------ RELATORIO
summary ""
summary "==================================================================="
summary " CAMPANHA NOTURNA v2 -- fim $(date +'%Y-%m-%d %H:%M:%S')"
summary "==================================================================="
summary ""
summary "INVENTARIO (oficial? overall/official/fallback):"
for N in 0 1 2 3 4 5 6; do
    line=$(python3 - "$N" 2>/dev/null <<'PY'
import json,os,sys
N=sys.argv[1]
base=f"/mnt/nids-captures/run{N}"
cs=f"{base}/run{N}_completion_status.json"; rs=f"{base}/run{N}_run_status.json"
if not os.path.exists(cs):
    print("AUSENTE"); sys.exit()
try:
    d=json.load(open(cs)); o=d.get("overall"); off=d.get("official")
    fbpct=""
    if os.path.exists(rs):
        s=json.load(open(rs)); oa=s.get("overlap_accounting",{}) or {}
        fb=oa.get("duration_fallback_flows",0); m=oa.get("matched_flows",0)
        if m: fbpct=f" fallback={100.0*fb/m:.1f}%"
        dr=s.get("diagnostic_reasons")
        if dr: fbpct+=f" diag={dr}"
    tag = "OFICIAL" if (o=="PASS" and off is True) else f"{o}/official={off}"
    print(f"{tag}{fbpct}")
except Exception as e:
    print(f"ILEGIVEL ({e})")
PY
)
    summary "  run$N: $line"
done
summary ""
summary "Log completo: $MAINLOG"
log "Campanha encerrada. Resumo: $SUMMARY"
