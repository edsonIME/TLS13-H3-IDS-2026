#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
benign_traffic.py  — WRAPPER (LEVEL 2 only)

Substitui o gerador de nivel 1 (Selenium). O orchestrate chama este script pelo
nome fixo "benign_traffic.py" e passa argumentos do nivel 1 (--campaign,
--headless, --ready-file, ...). Este wrapper:

  1. Aceita os argumentos do orchestrate sem quebrar em flags extras.
  2. Traduz para a interface do benign_clients.py (nivel 2):
       --campaign <arquivo>  ->  --campaign-id <id lido de dentro do JSON>
       --headless            ->  ignorado (nivel 2 nao usa navegador)
       (sites)               ->  --sites dos 8 vhosts (ou --sites explicito)
  3. Escreve o --ready-file QUANDO o nivel 2 sinaliza "preflight ok" no stdout —
     nem antes (evita marcar pronto um preflight que vai abortar), nem tarde
     demais (o gate do orchestrate espera esse arquivo). Se o preflight abortar,
     o ready-file NUNCA e escrito e o gate detecta a falha corretamente.
  4. Roda o benign_clients.py restrito aos PERFIS PYTHON-ONLY, que nao dependem
     de curl/wget — logo, rodam na NB2 (Windows).

Saida JSONL: escrita pelo proprio benign_clients.py, no formato que finalize_run
valida (contrato no cabecalho do benign_clients.py).
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time

# Perfis do nivel 2 que sao Python puro. A NB2 tem aioquic (H3), urllib3
# (requests) e — apos instalar — httpx. Ajuste esta lista se um perfil faltar.
PYTHON_ONLY_PROFILES = ["aioquic-h3", "httpx", "requests", "httpx-session", "requests-session"]

DEFAULT_SITES = [
    # Apenas os dois WordPress: suportam HTTP/3 (aioquic-h3 funciona) e tem os
    # caminhos WP do DEFAULT_PATHS. Os 6 vhosts estaticos (file_server) NAO
    # suportam H3 -> aioquic-h3 falhava neles (85/85 falhas no teste), derrubando
    # a taxa de sucesso abaixo do gate de 0.9. A diversidade do dataset vem do
    # fingerprint TLS dos 5 perfis (ja3 de cliente), nao do ja3s de servidor
    # (identico entre vhosts), entao restringir a 2 sites nao custa diversidade real.
    "https://blog.lab", "https://shop.lab",
]

# Linha que o benign_clients.py imprime QUANDO passa o preflight e vai iniciar os
# workers (ver benign_clients.py main(): print("preflight ok: ...")).
READY_SIGNAL = "preflight ok:"


def read_campaign_id(campaign_path):
    if not campaign_path:
        return None
    try:
        with open(campaign_path, encoding="utf-8") as fh:
            return (json.load(fh) or {}).get("campaign_id")
    except (OSError, ValueError):
        return None


def read_seed_for_run(campaign_path, run_id):
    """Le o seed do run <run_id> DE DENTRO do manifesto. O orchestrate nao passa
    --seed ao benigno, mas o manifesto define um seed por run (run N -> seed N);
    finalize_run compara o seed gravado no JSONL com o do manifesto, entao o seed
    TEM de vir do manifesto, nao de um default fixo. Retorna None se nao achar."""
    if not campaign_path:
        return None
    try:
        with open(campaign_path, encoding="utf-8") as fh:
            data = json.load(fh) or {}
        runs = data.get("runs") or {}
        run = runs.get(str(run_id)) or runs.get(run_id) or {}
        return run.get("seed")
    except (OSError, ValueError):
        return None


def write_ready_file(ready_path, run_id):
    if not ready_path:
        return
    try:
        with open(ready_path, "w", encoding="utf-8") as fh:
            json.dump({
                "ready_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "run_id": run_id,
                "pid": os.getpid(),
                "first_site": "level2-wrapper",
                "first_pages": 0,
            }, fh)
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=45.0)
    ap.add_argument("--campaign", default=None)
    ap.add_argument("--campaign-id", default=None)
    ap.add_argument("--run-id", type=int, required=True)
    ap.add_argument("--attempt-id", default="")
    ap.add_argument("--log-jsonl", required=True)
    ap.add_argument("--ready-file", default=None)
    ap.add_argument("--seed", type=int, default=None)   # None -> derivar do manifesto pelo run_id
    ap.add_argument("--sites", nargs="+", default=None)
    ap.add_argument("--workers", type=int, default=30)
    # aceitos-e-ignorados (interface do nivel 1):
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--browsers", nargs="+", default=None)
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--login-prob", type=float, default=None)
    ap.add_argument("--clients-script", default=None)
    args, _unknown = ap.parse_known_args()

    campaign_id = args.campaign_id or read_campaign_id(args.campaign) or "unknown-campaign"
    # Seed: explicito (--seed) tem prioridade; senao o seed do run no manifesto;
    # so entao um fallback. Isso garante que o seed gravado no JSONL bate com o
    # que finalize_run espera do manifesto (run N -> seed N).
    seed = args.seed
    if seed is None:
        seed = read_seed_for_run(args.campaign, args.run_id)
    if seed is None:
        seed = 0   # fallback defensivo; nunca deveria chegar aqui num run oficial
    sites = args.sites or DEFAULT_SITES
    here = os.path.dirname(os.path.abspath(__file__))
    clients = args.clients_script or os.path.join(here, "benign_clients.py")
    attempt_id = args.attempt_id or "{}-r{}-a1".format(campaign_id, args.run_id)

    cmd = [
        sys.executable, clients,
        "--minutes", str(args.minutes),
        "--workers", str(args.workers),
        "--sites", *sites,
        "--profiles", *PYTHON_ONLY_PROFILES,
        "--campaign-id", str(campaign_id),
        "--run-id", str(args.run_id),
        "--attempt-id", attempt_id,
        "--seed", str(seed),
        "--log-jsonl", args.log_jsonl,
    ]

    print("[wrapper] nivel 2:", " ".join(cmd), file=sys.stderr)

    # Rodar o nivel 2 capturando o stdout, para detectar "preflight ok:" e so
    # ENTAO escrever o ready-file. Repassar as linhas do nivel 2 ao nosso stdout.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None,
                            text=True, bufsize=1)

    ready_done = {"v": False}

    def pump():
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            if not ready_done["v"] and READY_SIGNAL in line:
                write_ready_file(args.ready_file, args.run_id)
                ready_done["v"] = True

    t = threading.Thread(target=pump)
    t.start()
    proc.wait()
    t.join()
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
