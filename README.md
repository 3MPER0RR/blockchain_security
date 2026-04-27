## install

python3 -m venv blockchain_security
source blockchain_security/bin/activate

pip install --upgrade pip

pip install requests ecdsa bitcoin hdwallet mnemonic pycoin bitcoinlib web3 eth-account eth-utils 

pandas numpy networkx matplotlib python-dotenv colorama tabulate

## Usage

Bitcoin    >>>>>> Bitcoin old tool in rust https://github.com/3MPER0RR/BTC-address-BIP-matching-tool

python3 blockchain_security_assessment.py --btc-address <addr>
python3 blockchain_security_assessment.py --btc-tx <txid>

Lightning

python3 blockchain_security_assessment.py --ln-node <pubkey>
python3 blockchain_security_assessment.py --ln-channel <channel_id>

Ethereum

python3 blockchain_security_assessment.py --evm-address 0x... --network ethereum
python3 blockchain_security_assessment.py --evm-tx 0x... --network polygon
python3 blockchain_security_assessment.py --evm-contract 0x... --network bsc

Solana

python3 blockchain_security_assessment.py --sol-balance <address>
python3 blockchain_security_assessment.py --sol-tx <signature>

CVE check

python3 blockchain_security_assessment.py --cve geth --cve-version 1.9.0

Full assessment multi-rete

python3 blockchain_security_assessment.py --full


## Functions

Bitcoin Address, TX, reuse, ports RPC, CVE Core

Lightning NetworkNode, channel, port, CVE LND

Ethereum Adress (EIP-55), balance, TX, smart contract, porte, CVE Geth

BSC / Polygon / Arbitrum / Optimism / AVAX / Base / Fantom balance, TX, contract, port (via --network)

Solana Adress, balance, TX

![Blockchainsecuritytool](BlockchainSecurityTool.png)
