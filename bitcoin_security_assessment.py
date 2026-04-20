#!/usr/bin/env python3
"""
Bitcoin / Blockchain Security Assessment Tool
=============================================
Uso ESCLUSIVAMENTE per ricerca di sicurezza legittima,
audit su wallet/nodi propri, e ambienti di test.

Funzionalità:
  1. Analisi sicurezza wallet (entropia chiavi private, formato BIP39)
  2. Analisi transazioni sospette su blockchain pubblica
  3. Scansione porte comuni nodo Bitcoin
  4. Rilevamento configurazioni RPC non sicure
  5. Analisi di indirizzi (riuso, tipo, ecc.)
  6. Check vulnerabilità note (CVE) su versioni Bitcoin Core
"""

import hashlib
import socket
import secrets
import json
import re
import sys
import struct
import time
import ipaddress
from typing import Optional

# ─── Dipendenze opzionali ──────────────────────────────────────────────────────
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("[WARN] 'requests' non installato. Alcune funzioni saranno disabilitate.")
    print("       Esegui: pip install requests\n")

try:
    import ecdsa
    ECDSA_OK = True
except ImportError:
    ECDSA_OK = False

# ─── Costanti Bitcoin ──────────────────────────────────────────────────────────
BITCOIN_PORTS     = [8332, 8333, 18332, 18333, 18443]  # mainnet rpc, mainnet p2p, testnet rpc, testnet p2p, regtest rpc
RPC_DEFAULT_USER  = ["bitcoin", "admin", "rpcuser", "user", "root"]
RPC_DEFAULT_PASS  = ["bitcoin", "password", "123456", "rpcpassword", "admin", ""]
BLOCKSTREAM_API   = "https://blockstream.info/api"

# ─── Util ──────────────────────────────────────────────────────────────────────

def banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║      Bitcoin / Blockchain Security Assessment Tool       ║
║      Solo per uso legittimo e autorizzato                ║
╚══════════════════════════════════════════════════════════╝
""")

def separator(title=""):
    width = 60
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─'*pad} {title} {'─'*pad}")
    else:
        print("─" * width)

# ─── 1. Analisi Wallet / Chiavi ────────────────────────────────────────────────

def check_private_key_entropy(hex_key: str) -> dict:
    """Verifica l'entropia di una chiave privata in formato hex."""
    result = {"key": hex_key[:8] + "...", "issues": [], "score": "OK"}
    try:
        key_bytes = bytes.fromhex(hex_key)
    except ValueError:
        return {"error": "Formato hex non valido"}

    if len(key_bytes) != 32:
        result["issues"].append(f"Lunghezza errata: {len(key_bytes)} byte (attesi 32)")
        result["score"] = "CRITICO"
        return result

    # Chiavi deboli note
    weak_patterns = [
        bytes([0]*32),
        bytes([0xFF]*32),
        bytes(range(32)),
        bytes(list(range(31, -1, -1))),
    ]
    if key_bytes in weak_patterns:
        result["issues"].append("Chiave privata debolissima / pattern sequenziale")
        result["score"] = "CRITICO"

    # Entropia di Shannon approssimata
    from collections import Counter
    counts = Counter(key_bytes)
    entropy = -sum((c/32) * __import__('math').log2(c/32) for c in counts.values())
    result["shannon_entropy"] = round(entropy, 3)
    if entropy < 3.5:
        result["issues"].append(f"Bassa entropia Shannon: {entropy:.3f} (soglia: 3.5)")
        result["score"] = "ATTENZIONE"

    # Byte ripetuti
    if len(set(key_bytes)) < 8:
        result["issues"].append("Pochi byte distinti — possibile chiave non casuale")
        result["score"] = "ATTENZIONE"

    if not result["issues"]:
        result["issues"].append("Nessuna anomalia rilevata")
    return result


def check_address_type(address: str) -> dict:
    """Identifica il tipo e i potenziali rischi di un indirizzo Bitcoin."""
    info = {"address": address, "type": "Sconosciuto", "issues": []}

    if re.match(r'^1[a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
        info["type"] = "P2PKH (Legacy)"
        info["issues"].append("Legacy: compatibile ma meno efficiente in fee")
    elif re.match(r'^3[a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
        info["type"] = "P2SH"
        info["issues"].append("P2SH: controlla che il redeem script sia sicuro")
    elif re.match(r'^bc1q[a-z0-9]{38,59}$', address):
        info["type"] = "P2WPKH (SegWit v0)"
    elif re.match(r'^bc1p[a-z0-9]{58}$', address):
        info["type"] = "P2TR (Taproot)"
    elif re.match(r'^tb1|^m[a-km-zA-HJ-NP-Z1-9]|^2[a-km-zA-HJ-NP-Z1-9]', address):
        info["type"] = "Testnet"
        info["issues"].append("Indirizzo testnet — non usare su mainnet")
    else:
        info["issues"].append("Formato non riconosciuto — possibile typo o rete diversa")

    return info


def check_address_reuse(address: str) -> dict:
    """Controlla riuso di indirizzo tramite API pubblica Blockstream."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    try:
        url = f"{BLOCKSTREAM_API}/address/{address}"
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json()
        tx_count = data.get("chain_stats", {}).get("tx_count", 0)
        result = {
            "address": address,
            "tx_count": tx_count,
            "funded_txo_count": data.get("chain_stats", {}).get("funded_txo_count", 0),
        }
        if tx_count > 1:
            result["warning"] = f"Indirizzo riutilizzato {tx_count} volte — rischio privacy!"
        else:
            result["info"] = "Nessun riuso rilevato"
        return result
    except Exception as e:
        return {"error": str(e)}


# ─── 2. Analisi Transazioni ────────────────────────────────────────────────────

def analyze_transaction(txid: str) -> dict:
    """Recupera e analizza una transazione per pattern sospetti."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    try:
        r = requests.get(f"{BLOCKSTREAM_API}/tx/{txid}", timeout=10)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        tx = r.json()
        issues = []

        # Fee analysis
        fee = tx.get("fee", 0)
        vsize = tx.get("weight", 400) // 4
        fee_rate = fee / vsize if vsize else 0
        if fee_rate > 500:
            issues.append(f"Fee molto alta: {fee_rate:.1f} sat/vB — possibile urgenza sospetta")
        if fee_rate < 1:
            issues.append(f"Fee bassissima: {fee_rate:.2f} sat/vB — potrebbe non confermare")

        # Input/Output count
        n_in  = len(tx.get("vin", []))
        n_out = len(tx.get("vout", []))
        if n_in > 20:
            issues.append(f"Molti input ({n_in}) — possibile CoinJoin o consolidamento sospetto")
        if n_out == 1:
            issues.append("Singolo output — nessun resto (sweep o pagamento esatto insolito)")
        if n_out > 50:
            issues.append(f"Molti output ({n_out}) — possibile mixing o distribuzione automatica")

        # RBF (Replace-By-Fee)
        rbf = any(inp.get("sequence", 0xFFFFFFFF) < 0xFFFFFFFE for inp in tx.get("vin", []))
        if rbf:
            issues.append("RBF abilitato — la transazione può essere sostituita")

        return {
            "txid": txid,
            "fee_sat": fee,
            "fee_rate_sat_vb": round(fee_rate, 2),
            "inputs": n_in,
            "outputs": n_out,
            "rbf_enabled": rbf,
            "confirmed": tx.get("status", {}).get("confirmed", False),
            "issues": issues if issues else ["Nessuna anomalia rilevata"],
        }
    except Exception as e:
        return {"error": str(e)}


# ─── 3. Scansione Porte Nodo Bitcoin ──────────────────────────────────────────

def scan_node_ports(host: str, timeout: float = 1.5) -> dict:
    """Scansiona le porte standard di un nodo Bitcoin su host specificato."""
    # Valida che sia IP privato o localhost (sicurezza)
    try:
        ip = ipaddress.ip_address(host)
        if not (ip.is_private or ip.is_loopback):
            return {"error": "Per sicurezza, scansiona solo IP privati/localhost"}
    except ValueError:
        if host not in ("localhost", "127.0.0.1", "::1"):
            return {"error": "Inserisci un hostname locale o IP privato"}

    results = {}
    for port in BITCOIN_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            code = s.connect_ex((host, port))
            s.close()
            results[port] = "APERTA" if code == 0 else "chiusa"
        except Exception:
            results[port] = "errore"

    open_ports = [p for p, v in results.items() if v == "APERTA"]
    warnings = []
    if 8332 in open_ports:
        warnings.append("Porta RPC 8332 aperta — verifica autenticazione e bind")
    if 18332 in open_ports:
        warnings.append("Porta RPC testnet 18332 aperta")

    return {"host": host, "ports": results, "open": open_ports, "warnings": warnings}


# ─── 4. Test Credenziali RPC Deboli ───────────────────────────────────────────

def test_rpc_weak_credentials(host: str = "127.0.0.1", port: int = 8332) -> dict:
    """
    Testa credenziali RPC di default su un nodo locale.
    SOLO su sistemi propri / autorizzati.
    """
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}

    url = f"http://{host}:{port}/"
    payload = json.dumps({
        "jsonrpc": "1.0",
        "id": "sectest",
        "method": "getblockchaininfo",
        "params": []
    })
    headers = {"Content-Type": "text/plain"}
    found = []

    for user in RPC_DEFAULT_USER:
        for pwd in RPC_DEFAULT_PASS:
            try:
                r = requests.post(url, data=payload, headers=headers,
                                  auth=(user, pwd), timeout=2)
                if r.status_code == 200:
                    found.append({"user": user, "password": pwd})
            except requests.exceptions.ConnectionError:
                return {"error": f"Nodo non raggiungibile su {host}:{port}"}
            except Exception:
                pass
            time.sleep(0.05)  # throttle

    if found:
        return {
            "status": "VULNERABILE",
            "found_credentials": found,
            "recommendation": "Cambia subito le credenziali RPC in bitcoin.conf"
        }
    return {"status": "OK", "info": "Nessuna credenziale di default trovata"}


# ─── 5. Check Versioni Bitcoin Core (CVE noti) ────────────────────────────────

KNOWN_VULN_VERSIONS = {
    "0.14": ["CVE-2017-18350 (buffer overflow P2P)"],
    "0.15": ["CVE-2018-17144 (double-spend / inflation bug)"],
    "0.16": ["CVE-2018-17144 (se prima di 0.16.3)"],
    "0.17": [],
    "0.18": [],
    "22.0": [],
}

def check_bitcoin_core_version(version_string: str) -> dict:
    """Controlla se una versione di Bitcoin Core ha CVE noti."""
    for ver, cves in KNOWN_VULN_VERSIONS.items():
        if version_string.startswith(ver) and cves:
            return {
                "version": version_string,
                "status": "VULNERABILE",
                "cves": cves,
                "recommendation": "Aggiorna all'ultima release stabile di Bitcoin Core"
            }
    return {
        "version": version_string,
        "status": "Nessuna CVE critica nota nel database locale",
        "note": "Verifica sempre su https://bitcoincore.org/en/releases/"
    }


# ─── 6. Generazione Report ────────────────────────────────────────────────────

def print_report(section: str, data: dict):
    separator(section)
    for k, v in data.items():
        if isinstance(v, list):
            print(f"  {k}:")
            for item in v:
                print(f"    • {item}")
        else:
            print(f"  {k}: {v}")


# ─── FULL ASSESSMENT ──────────────────────────────────────────────────────────

def run_full_assessment():
    """Esegue tutti i test predefiniti in sequenza."""
    banner()

    # 1. Analisi chiave privata casuale
    test_key = secrets.token_hex(32)
    print(f"[*] Chiave privata casuale generata: {test_key[:8]}...")
    print_report("Analisi Entropia Chiave Privata", check_private_key_entropy(test_key))

    # Chiave debole di esempio
    weak_key = "0" * 64
    print(f"\n[*] Test chiave privata DEBOLE: {weak_key[:8]}...")
    print_report("Analisi Chiave Debole", check_private_key_entropy(weak_key))

    # 2. Analisi indirizzi di esempio
    test_addresses = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",   # genesi legacy
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",  # segwit
        "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",  # taproot
    ]
    for addr in test_addresses:
        print_report("Tipo Indirizzo", check_address_type(addr))

    # 3. Scansione porte localhost
    print_report("Scansione Porte Nodo (localhost)", scan_node_ports("127.0.0.1"))

    # 4. Check versioni Bitcoin Core
    print_report("Check Versione Bitcoin Core", check_bitcoin_core_version("0.15.1"))
    print_report("Check Versione Bitcoin Core", check_bitcoin_core_version("26.0"))

    # 5. Analisi transazione genesis (richiede internet)
    if REQUESTS_OK:
        print("\n[*] Analisi transazione genesis coinbase...")
        genesis_tx = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        print_report("Analisi Transazione", analyze_transaction(genesis_tx))

    separator()
    print("\n✅ Assessment completato.\n")


# ─── MAIN / CLI ───────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="bitcoin_security_assessment.py",
        description="Bitcoin / Blockchain Security Assessment Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Esempi d'uso:
  Analisi indirizzo:
    python3 bitcoin_security_assessment.py --address bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq

  Analisi transazione:
    python3 bitcoin_security_assessment.py --tx 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

  Analisi chiave privata (hex):
    python3 bitcoin_security_assessment.py --key a1b2c3d4e5f6...

  Scansione porte nodo locale:
    python3 bitcoin_security_assessment.py --scan 127.0.0.1

  Test credenziali RPC deboli (solo nodo proprio):
    python3 bitcoin_security_assessment.py --rpc 127.0.0.1 --rpc-port 8332

  Check versione Bitcoin Core:
    python3 bitcoin_security_assessment.py --version 0.15.1

  Assessment completo con test predefiniti:
    python3 bitcoin_security_assessment.py --full

  Rete testnet (per --address e --tx):
    python3 bitcoin_security_assessment.py --address <addr> --testnet
        """
    )

    parser.add_argument(
        "--address", metavar="ADDR",
        help="Analizza un indirizzo Bitcoin (tipo, riuso, anomalie)"
    )
    parser.add_argument(
        "--tx", metavar="TXID",
        help="Analizza una transazione tramite TXID"
    )
    parser.add_argument(
        "--key", metavar="HEX",
        help="Analizza l'entropia di una chiave privata in formato hex (64 char)"
    )
    parser.add_argument(
        "--scan", metavar="HOST",
        help="Scansiona le porte di un nodo Bitcoin (solo IP privati/localhost)"
    )
    parser.add_argument(
        "--rpc", metavar="HOST",
        help="Testa credenziali RPC deboli su un nodo proprio"
    )
    parser.add_argument(
        "--rpc-port", metavar="PORT", type=int, default=8332,
        help="Porta RPC del nodo (default: 8332)"
    )
    parser.add_argument(
        "--version", metavar="VER",
        help="Controlla CVE noti per una versione di Bitcoin Core (es. 0.15.1)"
    )
    parser.add_argument(
        "--testnet", action="store_true",
        help="Usa endpoint testnet di Blockstream per --address e --tx"
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Esegui l'assessment completo con tutti i test predefiniti"
    )

    args = parser.parse_args()

    # Nessun argomento → mostra help
    if len(sys.argv) == 1:
        banner()
        parser.print_help()
        sys.exit(0)

    # Testnet switch
    global BLOCKSTREAM_API
    if args.testnet:
        BLOCKSTREAM_API = "https://blockstream.info/testnet/api"
        print("[INFO] Modalità testnet attiva\n")

    banner()
    executed = False

    if args.address:
        print_report("Tipo Indirizzo", check_address_type(args.address))
        print_report("Riuso Indirizzo", check_address_reuse(args.address))
        executed = True

    if args.tx:
        print_report("Analisi Transazione", analyze_transaction(args.tx))
        executed = True

    if args.key:
        print_report("Analisi Chiave Privata", check_private_key_entropy(args.key))
        executed = True

    if args.scan:
        print_report("Scansione Porte Nodo", scan_node_ports(args.scan))
        executed = True

    if args.rpc:
        print(f"[*] Test credenziali RPC su {args.rpc}:{args.rpc_port} ...")
        print_report("Test Credenziali RPC", test_rpc_weak_credentials(args.rpc, args.rpc_port))
        executed = True

    if args.version:
        print_report("Check Versione Bitcoin Core", check_bitcoin_core_version(args.version))
        executed = True

    if args.full:
        run_full_assessment()
        executed = True

    if executed:
        separator()
        print("\n✅ Analisi completata.\n")


if __name__ == "__main__":
    main()
