#!/usr/bin/env python3
"""
Multi-Network Blockchain Security Assessment Tool
==================================================
Reti supportate:
  • Bitcoin (BTC)       — mainnet / testnet
  • Lightning Network   — analisi nodi, canali, liquidità
  • Ethereum (ETH)      — indirizzi, transazioni, smart contract
  • BNB Smart Chain     — analisi token, contratti
  • Polygon (MATIC)     — analisi indirizzi e tx
  • Arbitrum / Optimism — L2 Ethereum
  • Avalanche (AVAX)    — C-Chain
  • Solana (SOL)        — indirizzi e transazioni

Uso ESCLUSIVAMENTE per ricerca di sicurezza legittima,
audit su wallet/nodi propri e ambienti di test.
"""

import hashlib
import socket
import secrets
import json
import re
import sys
import time
import ipaddress
import math
from collections import Counter
from typing import Optional

# ─── Dipendenze opzionali ─────────────────────────────────────────────────────
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("[WARN] 'requests' non installato → pip install requests\n")

try:
    import ecdsa
    ECDSA_OK = True
except ImportError:
    ECDSA_OK = False

# ══════════════════════════════════════════════════════════════════════════════
#  COSTANTI & ENDPOINT API
# ══════════════════════════════════════════════════════════════════════════════

BLOCKSTREAM_API  = "https://blockstream.info/api"
BLOCKSTREAM_TEST = "https://blockstream.info/testnet/api"
MEMPOOL_API      = "https://mempool.space/api"

# Ethereum & EVM-compatible chains — endpoint pubblici gratuiti
EVM_RPC = {
    "ethereum":  "https://eth.llamarpc.com",
    "bsc":       "https://bsc-dataseed.binance.org",
    "polygon":   "https://polygon-rpc.com",
    "arbitrum":  "https://arb1.arbitrum.io/rpc",
    "optimism":  "https://mainnet.optimism.io",
    "avalanche": "https://api.avax.network/ext/bc/C/rpc",
    "base":      "https://mainnet.base.org",
    "fantom":    "https://rpc.ftm.tools",
}

# Explorers per link utili
EXPLORERS = {
    "ethereum":  "https://etherscan.io",
    "bsc":       "https://bscscan.com",
    "polygon":   "https://polygonscan.com",
    "arbitrum":  "https://arbiscan.io",
    "optimism":  "https://optimistic.etherscan.io",
    "avalanche": "https://snowtrace.io",
    "base":      "https://basescan.org",
    "fantom":    "https://ftmscan.com",
    "solana":    "https://solscan.io",
    "bitcoin":   "https://mempool.space",
    "lightning": "https://amboss.space",
}

# Lightning Network — API pubblica
LIGHTNING_API = "https://mempool.space/api/v1/lightning"

# Solana — RPC pubblico
SOLANA_RPC = "https://api.mainnet-beta.solana.com"

# Porte nodi per rete
NODE_PORTS = {
    "bitcoin":   [8332, 8333, 18332, 18333, 18443],
    "ethereum":  [8545, 8546, 30303],
    "lightning": [9735, 9736],
    "bsc":       [8545, 30303],
    "polygon":   [8545, 30303],
}

RPC_DEFAULT_USER = ["bitcoin", "admin", "rpcuser", "user", "root", "ethereum"]
RPC_DEFAULT_PASS = ["bitcoin", "password", "123456", "rpcpassword", "admin", ""]

# CVE noti per client principali
KNOWN_CVE = {
    "bitcoin": {
        "0.14": ["CVE-2017-18350 (buffer overflow P2P)"],
        "0.15": ["CVE-2018-17144 (double-spend / inflation bug)"],
        "0.16": ["CVE-2018-17144 (se prima di 0.16.3)"],
    },
    "geth": {
        "1.9":  ["CVE-2020-26265 (DoS via GetBlockHeaders)"],
        "1.10": ["CVE-2021-39137 (consensus split EIP-1559)"],
    },
    "lnd": {
        "0.9":  ["CVE-2020-26895 (force-close channel exploit)"],
        "0.10": ["CVE-2020-26896 (payment preimage leak)"],
    },
}

# ══════════════════════════════════════════════════════════════════════════════
#  UTILITY
# ══════════════════════════════════════════════════════════════════════════════

def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║    Multi-Network Blockchain Security Assessment Tool         ║
║    BTC · Lightning · ETH · BSC · Polygon · AVAX · SOL       ║
║    Solo per uso legittimo e autorizzato                      ║
╚══════════════════════════════════════════════════════════════╝
""")

def separator(title=""):
    width = 64
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─'*pad} {title} {'─'*pad}")
    else:
        print("─" * width)

def print_report(section: str, data: dict):
    separator(section)
    for k, v in data.items():
        if isinstance(v, list):
            print(f"  {k}:")
            for item in v:
                print(f"    • {item}")
        elif isinstance(v, dict):
            print(f"  {k}:")
            for sk, sv in v.items():
                print(f"    {sk}: {sv}")
        else:
            print(f"  {k}: {v}")

def evm_rpc_call(network: str, method: str, params: list) -> Optional[dict]:
    """Esegue una chiamata JSON-RPC su una rete EVM."""
    if not REQUESTS_OK:
        return None
    url = EVM_RPC.get(network)
    if not url:
        return None
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        r = requests.post(url, json=payload, timeout=10)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None

def solana_rpc_call(method: str, params: list) -> Optional[dict]:
    """Esegue una chiamata JSON-RPC su Solana."""
    if not REQUESTS_OK:
        return None
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        r = requests.post(SOLANA_RPC, json=payload, timeout=10)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None

# ══════════════════════════════════════════════════════════════════════════════
#  1. CHIAVI PRIVATE — ANALISI ENTROPIA (comune a tutte le reti)
# ══════════════════════════════════════════════════════════════════════════════

def check_private_key_entropy(hex_key: str) -> dict:
    """Verifica l'entropia di una chiave privata hex (valida per BTC, ETH, EVM)."""
    result = {"key": hex_key[:8] + "...", "issues": [], "score": "OK"}
    try:
        key_bytes = bytes.fromhex(hex_key.strip())
    except ValueError:
        return {"error": "Formato hex non valido"}

    if len(key_bytes) != 32:
        result["issues"].append(f"Lunghezza errata: {len(key_bytes)} byte (attesi 32)")
        result["score"] = "CRITICO"
        return result

    weak_patterns = [bytes([0]*32), bytes([0xFF]*32), bytes(range(32)), bytes(range(31,-1,-1))]
    if key_bytes in weak_patterns:
        result["issues"].append("Chiave debolissima / pattern sequenziale")
        result["score"] = "CRITICO"

    counts = Counter(key_bytes)
    entropy = -sum((c/32) * math.log2(c/32) for c in counts.values())
    result["shannon_entropy"] = round(entropy, 3)
    if entropy < 3.5:
        result["issues"].append(f"Bassa entropia Shannon: {entropy:.3f} (soglia: 3.5)")
        result["score"] = "ATTENZIONE"

    if len(set(key_bytes)) < 8:
        result["issues"].append("Pochi byte distinti — probabile chiave non casuale")
        result["score"] = "ATTENZIONE"

    if not result["issues"]:
        result["issues"].append("Nessuna anomalia rilevata")
    return result

# ══════════════════════════════════════════════════════════════════════════════
#  2. BITCOIN — Indirizzi & Transazioni
# ══════════════════════════════════════════════════════════════════════════════

def btc_check_address(address: str) -> dict:
    """Identifica tipo e rischi di un indirizzo Bitcoin."""
    info = {"network": "Bitcoin", "address": address, "type": "Sconosciuto", "issues": []}
    if re.match(r'^1[a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
        info["type"] = "P2PKH (Legacy)"
        info["issues"].append("Legacy: fee meno efficienti, preferisci SegWit o Taproot")
    elif re.match(r'^3[a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
        info["type"] = "P2SH"
        info["issues"].append("P2SH: verifica che il redeem script sia sicuro")
    elif re.match(r'^bc1q[a-z0-9]{38,59}$', address):
        info["type"] = "P2WPKH (SegWit v0)"
    elif re.match(r'^bc1p[a-z0-9]{58}$', address):
        info["type"] = "P2TR (Taproot)"
    elif re.match(r'^(tb1|m[a-km-zA-HJ-NP-Z1-9]|2[a-km-zA-HJ-NP-Z1-9])', address):
        info["type"] = "Testnet"
        info["issues"].append("Indirizzo testnet — non usare su mainnet!")
    else:
        info["issues"].append("Formato non riconosciuto")
    info["explorer"] = f"https://mempool.space/address/{address}"
    return info

def btc_address_reuse(address: str, testnet: bool = False) -> dict:
    """Controlla riuso indirizzo via Blockstream API."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    base = BLOCKSTREAM_TEST if testnet else BLOCKSTREAM_API
    try:
        r = requests.get(f"{base}/address/{address}", timeout=10)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json()
        chain = data.get("chain_stats", {})
        mempool = data.get("mempool_stats", {})
        tx_count = chain.get("tx_count", 0)
        result = {
            "address": address,
            "tx_confermati": tx_count,
            "tx_mempool": mempool.get("tx_count", 0),
            "saldo_satoshi": chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0),
        }
        if tx_count > 1:
            result["warning"] = f"⚠ Indirizzo riutilizzato {tx_count} volte — rischio privacy!"
        else:
            result["privacy"] = "OK — nessun riuso rilevato"
        return result
    except Exception as e:
        return {"error": str(e)}

def btc_analyze_tx(txid: str, testnet: bool = False) -> dict:
    """Analizza una transazione Bitcoin."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    base = BLOCKSTREAM_TEST if testnet else BLOCKSTREAM_API
    try:
        r = requests.get(f"{base}/tx/{txid}", timeout=10)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        tx = r.json()
        issues = []
        fee = tx.get("fee", 0)
        vsize = tx.get("weight", 400) // 4
        fee_rate = fee / vsize if vsize else 0
        n_in  = len(tx.get("vin", []))
        n_out = len(tx.get("vout", []))
        rbf   = any(i.get("sequence", 0xFFFFFFFF) < 0xFFFFFFFE for i in tx.get("vin", []))
        coinbase = tx["vin"][0].get("is_coinbase", False) if tx.get("vin") else False

        if fee_rate > 500:
            issues.append(f"Fee molto alta: {fee_rate:.1f} sat/vB")
        if fee_rate < 1 and not coinbase:
            issues.append(f"Fee bassissima: {fee_rate:.2f} sat/vB")
        if n_in > 20:
            issues.append(f"Molti input ({n_in}) — possibile CoinJoin")
        if n_out == 1 and not coinbase:
            issues.append("Singolo output — sweep o pagamento senza resto")
        if n_out > 50:
            issues.append(f"Molti output ({n_out}) — possibile mixing")
        if rbf:
            issues.append("RBF abilitato — tx sostituibile")

        return {
            "network": "Bitcoin",
            "txid": txid[:16] + "...",
            "coinbase": coinbase,
            "confermata": tx.get("status", {}).get("confirmed", False),
            "fee_satoshi": fee,
            "fee_rate_sat_vb": round(fee_rate, 2),
            "input": n_in,
            "output": n_out,
            "rbf": rbf,
            "issues": issues or ["Nessuna anomalia rilevata"],
            "explorer": f"https://mempool.space/tx/{txid}",
        }
    except Exception as e:
        return {"error": str(e)}

# ══════════════════════════════════════════════════════════════════════════════
#  3. LIGHTNING NETWORK
# ══════════════════════════════════════════════════════════════════════════════

def ln_analyze_node(pubkey: str) -> dict:
    """Analizza un nodo Lightning Network tramite mempool.space API."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    try:
        r = requests.get(f"{LIGHTNING_API}/nodes/{pubkey}", timeout=10)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code} — nodo non trovato"}
        node = r.json()
        issues = []
        capacity = node.get("capacity", 0)
        channels = node.get("active_channel_count", 0)
        alias    = node.get("alias", "N/A")

        if channels == 0:
            issues.append("Nodo senza canali attivi")
        if capacity < 1_000_000:
            issues.append(f"Capacità bassa: {capacity} sat — liquidità limitata")
        if capacity > 1_000_000_000:
            issues.append(f"Nodo ad alta capacità: {capacity} sat — target appetibile")

        # Verifica Tor
        addrs = [a.get("addr", "") for a in node.get("addresses", [])]
        has_tor  = any(".onion" in a for a in addrs)
        has_clear = any(".onion" not in a and a for a in addrs)
        if has_clear and not has_tor:
            issues.append("IP pubblico esposto — considera Tor per privacy")

        return {
            "network": "Lightning Network",
            "alias": alias,
            "pubkey": pubkey[:20] + "...",
            "canali_attivi": channels,
            "capacita_sat": capacity,
            "capacita_btc": round(capacity / 1e8, 6),
            "indirizzi": addrs,
            "tor": has_tor,
            "issues": issues or ["Nessuna anomalia rilevata"],
            "explorer": f"https://amboss.space/node/{pubkey}",
        }
    except Exception as e:
        return {"error": str(e)}

def ln_analyze_channel(channel_id: str) -> dict:
    """Analizza un canale Lightning Network."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    try:
        r = requests.get(f"{LIGHTNING_API}/channels/{channel_id}", timeout=10)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        ch = r.json()
        issues = []
        capacity = ch.get("capacity", 0)
        if capacity < 100_000:
            issues.append("Canale a bassa capacità — routing inefficiente")
        if not ch.get("active", True):
            issues.append("Canale inattivo")

        return {
            "network": "Lightning Network",
            "channel_id": channel_id,
            "capacita_sat": capacity,
            "attivo": ch.get("active", False),
            "node1": ch.get("node1_pub", "N/A")[:20] + "...",
            "node2": ch.get("node2_pub", "N/A")[:20] + "...",
            "issues": issues or ["Nessuna anomalia rilevata"],
        }
    except Exception as e:
        return {"error": str(e)}

def ln_scan_ports(host: str) -> dict:
    """Scansiona porte Lightning Network su host locale."""
    try:
        ip = ipaddress.ip_address(host)
        if not (ip.is_private or ip.is_loopback):
            return {"error": "Solo IP privati/localhost per sicurezza"}
    except ValueError:
        if host not in ("localhost", "127.0.0.1", "::1"):
            return {"error": "Inserisci un hostname locale o IP privato"}

    results = {}
    for port in NODE_PORTS["lightning"]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        results[port] = "APERTA" if s.connect_ex((host, port)) == 0 else "chiusa"
        s.close()

    warnings = []
    if results.get(9735) == "APERTA":
        warnings.append("Porta P2P Lightning 9735 aperta — verifica autenticazione macaroon")
    return {"host": host, "porte": results, "warnings": warnings or ["Nessun problema rilevato"]}

# ══════════════════════════════════════════════════════════════════════════════
#  4. ETHEREUM & EVM CHAINS (ETH, BSC, Polygon, Arbitrum, Optimism, AVAX, Base)
# ══════════════════════════════════════════════════════════════════════════════

def evm_check_address(address: str) -> dict:
    """Valida un indirizzo EVM (Ethereum-style 0x...)."""
    info = {"address": address, "issues": []}
    if not re.match(r'^0x[0-9a-fA-F]{40}$', address):
        info["issues"].append("Formato non valido — un indirizzo EVM ha 42 caratteri (0x + 40 hex)")
        info["valid"] = False
        return info
    info["valid"] = True

    # EIP-55 checksum check
    addr = address[2:]
    addr_hash = hashlib.sha3_256(addr.lower().encode()).hexdigest()  # nota: Keccak-256 ideale ma sha3 è approssimazione
    checksum = "0x" + "".join(
        c.upper() if int(addr_hash[i], 16) >= 8 else c.lower()
        for i, c in enumerate(addr.lower())
    )
    if address != checksum and address != address.lower():
        info["issues"].append("Checksum EIP-55 non valido — possibile errore di copia")
    else:
        info["checksum_eip55"] = "OK"

    # Indirizzi noti a rischio
    zero_addr = "0x0000000000000000000000000000000000000000"
    burn_addr  = "0x000000000000000000000000000000000000dEaD"
    if address.lower() == zero_addr:
        info["issues"].append("Indirizzo zero — qualsiasi invio sarà perso!")
    if address.lower() == burn_addr.lower():
        info["issues"].append("Burn address — i fondi inviati qui sono permanentemente distrutti")

    return info

def evm_get_balance(address: str, network: str = "ethereum") -> dict:
    """Recupera il saldo nativo di un indirizzo EVM."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    result = evm_rpc_call(network, "eth_getBalance", [address, "latest"])
    if not result or "result" not in result:
        return {"error": "RPC non raggiungibile o risposta vuota"}
    wei = int(result["result"], 16)
    decimals = {"ethereum": 18, "bsc": 18, "polygon": 18, "arbitrum": 18,
                "optimism": 18, "avalanche": 18, "base": 18, "fantom": 18}
    dec = decimals.get(network, 18)
    native = wei / (10 ** dec)
    symbols = {"ethereum": "ETH", "bsc": "BNB", "polygon": "MATIC",
               "arbitrum": "ETH", "optimism": "ETH", "avalanche": "AVAX",
               "base": "ETH", "fantom": "FTM"}
    return {
        "network": network,
        "address": address,
        "saldo_wei": wei,
        f"saldo_{symbols.get(network,'native')}": round(native, 8),
        "explorer": f"{EXPLORERS.get(network,'')}/address/{address}",
    }

def evm_analyze_tx(txhash: str, network: str = "ethereum") -> dict:
    """Analizza una transazione EVM."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    result = evm_rpc_call(network, "eth_getTransactionByHash", [txhash])
    if not result or not result.get("result"):
        return {"error": "Transazione non trovata o RPC non raggiungibile"}
    tx = result["result"]
    receipt = evm_rpc_call(network, "eth_getTransactionReceipt", [txhash])
    issues = []

    gas_price = int(tx.get("gasPrice", "0x0"), 16) / 1e9  # Gwei
    gas_limit = int(tx.get("gas", "0x0"), 16)
    value_wei = int(tx.get("value", "0x0"), 16)
    value_eth = value_wei / 1e18
    to_addr   = tx.get("to")
    data      = tx.get("input", "0x")
    is_contract_call = data != "0x" and data != ""

    if gas_price > 500:
        issues.append(f"Gas price molto alto: {gas_price:.1f} Gwei")
    if gas_price < 0.001 and gas_price > 0:
        issues.append(f"Gas price bassissimo: {gas_price:.4f} Gwei — rischio stuck tx")
    if not to_addr:
        issues.append("Nessun destinatario — probabile deploy di contratto")
    if is_contract_call:
        issues.append(f"Chiamata a contratto — input data: {data[:20]}...")
    if value_eth == 0 and not is_contract_call:
        issues.append("Valore zero senza data — transazione vuota")

    status = "N/A"
    if receipt and receipt.get("result"):
        status_hex = receipt["result"].get("status", "0x1")
        status = "SUCCESS" if status_hex == "0x1" else "FAILED ⚠"
        if status_hex != "0x1":
            issues.append("Transazione FALLITA on-chain")

    return {
        "network": network,
        "txhash": txhash[:18] + "...",
        "da": tx.get("from", "N/A"),
        "a": to_addr or "contract deploy",
        "valore_eth": round(value_eth, 8),
        "gas_price_gwei": round(gas_price, 4),
        "gas_limit": gas_limit,
        "chiamata_contratto": is_contract_call,
        "stato": status,
        "issues": issues or ["Nessuna anomalia rilevata"],
        "explorer": f"{EXPLORERS.get(network,'')}/tx/{txhash}",
    }

def evm_check_contract(address: str, network: str = "ethereum") -> dict:
    """Verifica se un indirizzo è un contratto e ne analizza il bytecode base."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    result = evm_rpc_call(network, "eth_getCode", [address, "latest"])
    if not result or "result" not in result:
        return {"error": "RPC non raggiungibile"}
    code = result["result"]
    issues = []

    if code == "0x" or code == "":
        return {
            "network": network,
            "address": address,
            "tipo": "EOA (wallet normale, non contratto)",
            "issues": ["Nessuna anomalia — è un wallet standard"],
        }

    code_size = (len(code) - 2) // 2  # bytes
    issues.append(f"È un contratto — bytecode: {code_size} byte")

    # Pattern sospetti nel bytecode (hex)
    suspicious = {
        "selfdestruct": "ff",
        "delegatecall": "f4",
        "create2":      "f5",
    }
    found_ops = []
    for name, opcode in suspicious.items():
        if opcode in code[2:]:
            found_ops.append(name)

    if "selfdestruct" in found_ops:
        issues.append("⚠ SELFDESTRUCT trovato — contratto può autodistruggersi")
    if "delegatecall" in found_ops:
        issues.append("⚠ DELEGATECALL trovato — possibile proxy o rischio di upgrade malevolo")
    if "create2" in found_ops:
        issues.append("CREATE2 trovato — può deployare contratti a indirizzi prevedibili")

    return {
        "network": network,
        "address": address,
        "tipo": "Smart Contract",
        "bytecode_byte": code_size,
        "opcode_sospetti": found_ops or ["nessuno"],
        "issues": issues,
        "explorer": f"{EXPLORERS.get(network,'')}/address/{address}#code",
    }

def evm_scan_ports(host: str, network: str = "ethereum") -> dict:
    """Scansiona porte di un nodo EVM locale."""
    try:
        ip = ipaddress.ip_address(host)
        if not (ip.is_private or ip.is_loopback):
            return {"error": "Solo IP privati/localhost"}
    except ValueError:
        if host not in ("localhost", "127.0.0.1", "::1"):
            return {"error": "Inserisci IP privato o localhost"}

    ports = NODE_PORTS.get(network, NODE_PORTS["ethereum"])
    results = {}
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        results[port] = "APERTA" if s.connect_ex((host, port)) == 0 else "chiusa"
        s.close()

    warnings = []
    if results.get(8545) == "APERTA":
        warnings.append("⚠ Porta RPC JSON 8545 aperta senza auth — rischio furto fondi!")
    if results.get(8546) == "APERTA":
        warnings.append("Porta WebSocket 8546 aperta — verifica whitelist IP")
    return {
        "network": network,
        "host": host,
        "porte": results,
        "warnings": warnings or ["Nessun problema rilevato"],
    }

# ══════════════════════════════════════════════════════════════════════════════
#  5. SOLANA
# ══════════════════════════════════════════════════════════════════════════════

def solana_check_address(address: str) -> dict:
    """Valida un indirizzo Solana (base58, 32-44 char)."""
    info = {"network": "Solana", "address": address, "issues": []}
    if not re.match(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$', address):
        info["issues"].append("Formato non valido — indirizzo Solana base58 atteso (32-44 char)")
        info["valid"] = False
    else:
        info["valid"] = True
        info["issues"].append("Formato valido")
    info["explorer"] = f"https://solscan.io/account/{address}"
    return info

def solana_get_balance(address: str) -> dict:
    """Recupera il saldo SOL di un indirizzo."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    result = solana_rpc_call("getBalance", [address])
    if not result or "result" not in result:
        return {"error": "RPC Solana non raggiungibile"}
    lamports = result["result"].get("value", 0)
    sol = lamports / 1e9
    issues = []
    if sol == 0:
        issues.append("Saldo zero — wallet vuoto o indirizzo errato")
    return {
        "network": "Solana",
        "address": address,
        "saldo_lamports": lamports,
        "saldo_SOL": round(sol, 6),
        "issues": issues or ["Nessuna anomalia"],
        "explorer": f"https://solscan.io/account/{address}",
    }

def solana_analyze_tx(signature: str) -> dict:
    """Analizza una transazione Solana tramite firma."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    result = solana_rpc_call("getTransaction", [signature, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
    if not result or not result.get("result"):
        return {"error": "Transazione non trovata"}
    tx = result["result"]
    meta = tx.get("meta", {})
    issues = []

    err = meta.get("err")
    fee = meta.get("fee", 0)
    if err:
        issues.append(f"Transazione FALLITA: {err}")
    if fee > 100_000:
        issues.append(f"Fee alta: {fee} lamports")

    logs = meta.get("logMessages", [])
    for log in logs:
        if "error" in log.lower() or "failed" in log.lower():
            issues.append(f"Log errore: {log[:80]}")

    return {
        "network": "Solana",
        "signature": signature[:20] + "...",
        "slot": tx.get("slot", "N/A"),
        "fee_lamports": fee,
        "stato": "FAILED ⚠" if err else "SUCCESS",
        "log_count": len(logs),
        "issues": issues or ["Nessuna anomalia rilevata"],
        "explorer": f"https://solscan.io/tx/{signature}",
    }

# ══════════════════════════════════════════════════════════════════════════════
#  6. SCANSIONE PORTE NODO BITCOIN
# ══════════════════════════════════════════════════════════════════════════════

def btc_scan_ports(host: str) -> dict:
    """Scansiona porte standard di un nodo Bitcoin su host locale."""
    try:
        ip = ipaddress.ip_address(host)
        if not (ip.is_private or ip.is_loopback):
            return {"error": "Solo IP privati/localhost"}
    except ValueError:
        if host not in ("localhost", "127.0.0.1", "::1"):
            return {"error": "Inserisci IP privato o localhost"}

    results = {}
    for port in NODE_PORTS["bitcoin"]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        results[port] = "APERTA" if s.connect_ex((host, port)) == 0 else "chiusa"
        s.close()

    warnings = []
    if results.get(8332) == "APERTA":
        warnings.append("Porta RPC 8332 aperta — verifica autenticazione")
    if results.get(18332) == "APERTA":
        warnings.append("Porta RPC testnet 18332 aperta")

    return {
        "network": "Bitcoin",
        "host": host,
        "porte": results,
        "warnings": warnings or ["Nessun problema rilevato"],
    }

# ══════════════════════════════════════════════════════════════════════════════
#  7. CREDENZIALI RPC DEBOLI (Bitcoin)
# ══════════════════════════════════════════════════════════════════════════════

def test_rpc_weak_credentials(host: str = "127.0.0.1", port: int = 8332) -> dict:
    """Testa credenziali RPC deboli su nodo Bitcoin proprio."""
    if not REQUESTS_OK:
        return {"error": "requests non disponibile"}
    url = f"http://{host}:{port}/"
    payload = json.dumps({"jsonrpc":"1.0","id":"sectest","method":"getblockchaininfo","params":[]})
    headers = {"Content-Type": "text/plain"}
    found = []
    for user in RPC_DEFAULT_USER:
        for pwd in RPC_DEFAULT_PASS:
            try:
                r = requests.post(url, data=payload, headers=headers, auth=(user, pwd), timeout=2)
                if r.status_code == 200:
                    found.append({"user": user, "password": pwd})
            except requests.exceptions.ConnectionError:
                return {"error": f"Nodo non raggiungibile su {host}:{port}"}
            except Exception:
                pass
            time.sleep(0.05)
    if found:
        return {"status": "VULNERABILE ⚠", "credenziali_trovate": found,
                "recommendation": "Aggiorna rpcuser e rpcpassword in bitcoin.conf"}
    return {"status": "OK", "info": "Nessuna credenziale di default trovata"}

# ══════════════════════════════════════════════════════════════════════════════
#  8. CVE CHECK — Bitcoin Core, Geth, LND
# ══════════════════════════════════════════════════════════════════════════════

def check_client_version(client: str, version: str) -> dict:
    """Controlla CVE noti per Bitcoin Core, Geth o LND."""
    client = client.lower()
    cve_db = KNOWN_CVE.get(client)
    if not cve_db:
        return {"error": f"Client '{client}' non nel database. Supportati: {list(KNOWN_CVE.keys())}"}
    for ver_prefix, cves in cve_db.items():
        if version.startswith(ver_prefix) and cves:
            return {
                "client": client,
                "version": version,
                "status": "VULNERABILE ⚠",
                "cves": cves,
                "recommendation": f"Aggiorna {client} all'ultima versione stabile",
            }
    return {
        "client": client,
        "version": version,
        "status": "Nessuna CVE critica nel database locale",
        "note": "Verifica sempre il changelog ufficiale del client",
    }

# ══════════════════════════════════════════════════════════════════════════════
#  9. FULL ASSESSMENT
# ══════════════════════════════════════════════════════════════════════════════

def run_full_assessment():
    """Esegue una batteria completa di test su tutte le reti."""
    banner()

    # ── Chiavi private
    test_key = secrets.token_hex(32)
    print(f"[*] Chiave privata casuale: {test_key[:8]}...")
    print_report("Entropia Chiave (BTC/ETH/EVM)", check_private_key_entropy(test_key))
    print_report("Entropia Chiave DEBOLE", check_private_key_entropy("0" * 64))

    # ── Bitcoin
    print_report("BTC — Tipo Indirizzo (Legacy)",  btc_check_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
    print_report("BTC — Tipo Indirizzo (SegWit)",  btc_check_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"))
    print_report("BTC — Tipo Indirizzo (Taproot)", btc_check_address("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"))
    print_report("BTC — Porte Nodo Locale",        btc_scan_ports("127.0.0.1"))
    print_report("BTC — CVE Bitcoin Core 0.15.1",  check_client_version("bitcoin", "0.15.1"))
    print_report("BTC — CVE Bitcoin Core 26.0",    check_client_version("bitcoin", "26.0"))

    if REQUESTS_OK:
        print_report("BTC — Analisi TX Genesis", btc_analyze_tx(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"))

    # ── Lightning Network
    print_report("LN — Porte Nodo Locale", ln_scan_ports("127.0.0.1"))
    print_report("LN — CVE LND 0.9",       check_client_version("lnd", "0.9.0"))

    # ── Ethereum
    eth_addr = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    print_report("ETH — Validazione Indirizzo",  evm_check_address(eth_addr))
    print_report("ETH — Porte Nodo Locale",      evm_scan_ports("127.0.0.1", "ethereum"))
    print_report("ETH — CVE Geth 1.9",           check_client_version("geth", "1.9.0"))

    if REQUESTS_OK:
        print_report("ETH — Saldo Indirizzo",    evm_get_balance(eth_addr, "ethereum"))
        print_report("ETH — Check Contratto",    evm_check_contract(eth_addr, "ethereum"))

    # ── Solana
    sol_addr = "So11111111111111111111111111111111111111112"
    print_report("SOL — Validazione Indirizzo", solana_check_address(sol_addr))
    if REQUESTS_OK:
        print_report("SOL — Saldo", solana_get_balance(sol_addr))

    separator()
    print("\n✅ Assessment completo terminato.\n")

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN / CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="blockchain_security_assessment.py",
        description="Multi-Network Blockchain Security Assessment Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ESEMPI D'USO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ── BITCOIN ───────────────────────────────────
  Analisi indirizzo BTC:
    python3 blockchain_security_assessment.py --btc-address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

  Analisi TX Bitcoin:
    python3 blockchain_security_assessment.py --btc-tx <txid>

  Scansione porte nodo BTC:
    python3 blockchain_security_assessment.py --btc-scan 127.0.0.1

  Test credenziali RPC Bitcoin:
    python3 blockchain_security_assessment.py --rpc 127.0.0.1 --rpc-port 8332

  ── LIGHTNING NETWORK ─────────────────────────
  Analisi nodo Lightning:
    python3 blockchain_security_assessment.py --ln-node <pubkey>

  Analisi canale Lightning:
    python3 blockchain_security_assessment.py --ln-channel <channel_id>

  Scansione porte nodo Lightning:
    python3 blockchain_security_assessment.py --ln-scan 127.0.0.1

  ── ETHEREUM & EVM CHAINS ─────────────────────
  Analisi indirizzo ETH:
    python3 blockchain_security_assessment.py --evm-address 0xABC... --network ethereum

  Saldo indirizzo su BSC:
    python3 blockchain_security_assessment.py --evm-balance 0xABC... --network bsc

  Analisi TX su Polygon:
    python3 blockchain_security_assessment.py --evm-tx 0xABC... --network polygon

  Analisi smart contract:
    python3 blockchain_security_assessment.py --evm-contract 0xABC... --network ethereum

  Scansione porte nodo Ethereum:
    python3 blockchain_security_assessment.py --evm-scan 127.0.0.1 --network ethereum

  Reti EVM disponibili:
    ethereum | bsc | polygon | arbitrum | optimism | avalanche | base | fantom

  ── SOLANA ────────────────────────────────────
  Analisi indirizzo SOL:
    python3 blockchain_security_assessment.py --sol-address <address>

  Saldo SOL:
    python3 blockchain_security_assessment.py --sol-balance <address>

  Analisi TX Solana:
    python3 blockchain_security_assessment.py --sol-tx <signature>

  ── CHIAVI & CVE ──────────────────────────────
  Analisi entropia chiave privata:
    python3 blockchain_security_assessment.py --key <hex64>

  Check CVE client (bitcoin | geth | lnd):
    python3 blockchain_security_assessment.py --cve bitcoin --cve-version 0.15.1

  ── ASSESSMENT COMPLETO ───────────────────────
    python3 blockchain_security_assessment.py --full
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
    )

    # ── Bitcoin
    btc = parser.add_argument_group("Bitcoin (BTC)")
    btc.add_argument("--btc-address", metavar="ADDR",   help="Analisi indirizzo Bitcoin")
    btc.add_argument("--btc-tx",      metavar="TXID",   help="Analisi transazione Bitcoin")
    btc.add_argument("--btc-scan",    metavar="HOST",   help="Scansione porte nodo Bitcoin")
    btc.add_argument("--testnet",     action="store_true", help="Usa endpoint testnet per BTC")
    btc.add_argument("--rpc",         metavar="HOST",   help="Test credenziali RPC Bitcoin (solo nodo proprio)")
    btc.add_argument("--rpc-port",    metavar="PORT", type=int, default=8332, help="Porta RPC (default: 8332)")

    # ── Lightning
    ln = parser.add_argument_group("Lightning Network (LN)")
    ln.add_argument("--ln-node",    metavar="PUBKEY",     help="Analisi nodo Lightning")
    ln.add_argument("--ln-channel", metavar="CHANNEL_ID", help="Analisi canale Lightning")
    ln.add_argument("--ln-scan",    metavar="HOST",       help="Scansione porte nodo Lightning")

    # ── EVM
    evm = parser.add_argument_group("Ethereum & EVM (ETH, BSC, Polygon, Arbitrum, Optimism, AVAX, Base, Fantom)")
    evm.add_argument("--evm-address",  metavar="ADDR",   help="Validazione indirizzo EVM")
    evm.add_argument("--evm-balance",  metavar="ADDR",   help="Saldo nativo indirizzo EVM")
    evm.add_argument("--evm-tx",       metavar="TXHASH", help="Analisi transazione EVM")
    evm.add_argument("--evm-contract", metavar="ADDR",   help="Analisi smart contract EVM")
    evm.add_argument("--evm-scan",     metavar="HOST",   help="Scansione porte nodo EVM")
    evm.add_argument("--network",      metavar="NET", default="ethereum",
                     help="Rete EVM (default: ethereum)")

    # ── Solana
    sol = parser.add_argument_group("Solana (SOL)")
    sol.add_argument("--sol-address", metavar="ADDR",  help="Validazione indirizzo Solana")
    sol.add_argument("--sol-balance", metavar="ADDR",  help="Saldo SOL di un indirizzo")
    sol.add_argument("--sol-tx",      metavar="SIG",   help="Analisi transazione Solana")

    # ── Comuni
    common = parser.add_argument_group("Comuni")
    common.add_argument("--key",         metavar="HEX",    help="Analisi entropia chiave privata (hex 64 char)")
    common.add_argument("--cve",         metavar="CLIENT", help="Check CVE: bitcoin | geth | lnd")
    common.add_argument("--cve-version", metavar="VER",    help="Versione da controllare (es. 0.15.1)")
    common.add_argument("--full",        action="store_true", help="Assessment completo multi-rete")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        banner()
        parser.print_help()
        sys.exit(0)

    banner()
    executed = False

    # ── Bitcoin
    if args.btc_address:
        print_report("BTC — Tipo Indirizzo",  btc_check_address(args.btc_address))
        print_report("BTC — Riuso Indirizzo", btc_address_reuse(args.btc_address, args.testnet))
        executed = True
    if args.btc_tx:
        print_report("BTC — Analisi Transazione", btc_analyze_tx(args.btc_tx, args.testnet))
        executed = True
    if args.btc_scan:
        print_report("BTC — Scansione Porte", btc_scan_ports(args.btc_scan))
        executed = True
    if args.rpc:
        print_report("BTC — Test Credenziali RPC", test_rpc_weak_credentials(args.rpc, args.rpc_port))
        executed = True

    # ── Lightning
    if args.ln_node:
        print_report("LN — Analisi Nodo", ln_analyze_node(args.ln_node))
        executed = True
    if args.ln_channel:
        print_report("LN — Analisi Canale", ln_analyze_channel(args.ln_channel))
        executed = True
    if args.ln_scan:
        print_report("LN — Scansione Porte", ln_scan_ports(args.ln_scan))
        executed = True

    # ── EVM
    if args.evm_address:
        print_report(f"EVM [{args.network}] — Validazione Indirizzo", evm_check_address(args.evm_address))
        executed = True
    if args.evm_balance:
        print_report(f"EVM [{args.network}] — Saldo", evm_get_balance(args.evm_balance, args.network))
        executed = True
    if args.evm_tx:
        print_report(f"EVM [{args.network}] — Analisi TX", evm_analyze_tx(args.evm_tx, args.network))
        executed = True
    if args.evm_contract:
        print_report(f"EVM [{args.network}] — Analisi Contratto", evm_check_contract(args.evm_contract, args.network))
        executed = True
    if args.evm_scan:
        print_report(f"EVM [{args.network}] — Scansione Porte", evm_scan_ports(args.evm_scan, args.network))
        executed = True

    # ── Solana
    if args.sol_address:
        print_report("SOL — Validazione Indirizzo", solana_check_address(args.sol_address))
        executed = True
    if args.sol_balance:
        print_report("SOL — Saldo", solana_get_balance(args.sol_balance))
        executed = True
    if args.sol_tx:
        print_report("SOL — Analisi Transazione", solana_analyze_tx(args.sol_tx))
        executed = True

    # ── Comuni
    if args.key:
        print_report("Analisi Chiave Privata", check_private_key_entropy(args.key))
        executed = True
    if args.cve:
        version = args.cve_version or "0.0.0"
        print_report(f"CVE Check — {args.cve} {version}", check_client_version(args.cve, version))
        executed = True
    if args.full:
        run_full_assessment()
        executed = True

    if executed:
        separator()
        print("\n✅ Analisi completata.\n")


if __name__ == "__main__":
    main()
