# LibChain: Blockchain-Based Library Book Lending Tracker (ALU Summative)

A complete C implementation of an immutable, signed, proof-of-work lending ledger for a university library:
multi-copy inventory, reservations, renewals, overdue fines, token rewards (UTXO **and** account models),
solo / pool / cloud mining, ECDSA signatures, fraud detection, tamper detection and disk persistence.

## 1. Dependencies

| Need | Notes |
|---|---|
| `gcc` (any C11 compiler) | tested with gcc 13 |
| OpenSSL **libcrypto** + headers | SHA-256 and ECDSA (secp256k1) |
| `make` | |

```bash
# Debian / Ubuntu / WSL
sudo apt-get install build-essential libssl-dev
# macOS (Homebrew)
brew install openssl   # then: make CFLAGS="-I$(brew --prefix openssl)/include" LDFLAGS="-L$(brew --prefix openssl)/lib -lcrypto"
```

## 2. Compile

```bash
make            # builds ./libchain with  gcc -Wall -Wextra -O2   (zero warnings)
make clean      # removes binary and saved state
```

Manual equivalent: `gcc -Wall -Wextra -O2 -o libchain src/*.c -lcrypto`

## 3. Run

Run from the project folder (it must contain `books.txt`, `copies.txt`, `members.txt`).

```bash
./libchain                              # interactive shell ("help" lists every command)
./libchain --difficulty 3 --model account
./libchain borrow_book M001 B001        # single-command mode (state persists on disk)
./libchain < demo/demo_commands.txt     # scripted run (the demo flow)
```

Start-up behaviour: if `chain.dat` exists the full state is restored and the session is **locked**
until you run `validate_chain` (in single-command mode the chain is validated automatically first);
otherwise a new chain with a genesis block is created from the three input files.

Input files (comma separated, `#` comments allowed):

```
books.txt    B001,Introduction to Algorithms,Thomas Cormen
copies.txt   C001,B001,NEW            (copy_id, book_id, NEW|GOOD|WORN)
members.txt  M001,Alice Uwase,SE101
```

A missing or empty file prints an error and the program refuses to start.

## 4. Switching between the UTXO and account-based models

Both ledgers are updated for every confirmed token transaction so they always agree; the selected model
decides which one validates spending and which view is printed after every mined block.

```bash
./libchain --model utxo        # or: --model account       (start-up option)
libchain> set_model account    # menu/command option, applies to the rest of the session
libchain> utxo_view            # full UTXO set (always available)
libchain> account_balance M001 # balance + account nonce
```

Fee: every transfer pays `tx_fee` (default 1 coin) to the block's miner. UTXO transfers produce a
recipient output, a **change** output and a fee output. Change with `config tx_fee N`.

## 5. Setting mining difficulty (1 to 4)

```bash
./libchain --difficulty 4           # command-line argument
libchain> set_difficulty 3          # menu command
libchain> difficulty_status         # target prefix, expected attempts, last attempt count
```

Difficulty *d* means the block hash must begin with *d* hex zeros (`2` -> `00`, `4` -> `0000`).

## 6. Testing the mining simulations

```bash
libchain> borrow_book M001 B001
libchain> mine_solo            # one miner, full reward, prints hash-attempt count
libchain> borrow_book M002 B002
libchain> mine_pool            # 4 miners with random hash rates, 2% pool fee, share table
libchain> borrow_book M003 B003
libchain> mine_cloud 3         # rent 1-5 rounds; gross / fees / net profit + loss warning
libchain> config cloud_fee 90  # make renting unprofitable to see the warning
```

Every mining command needs at least one mineable request in the pool (`pool_view`).

## 7. Automated tests

```bash
./tests/run_tests.sh           # 8 scenarios, 43 expected-vs-actual checks
cat tests/results.txt          # last recorded run (43 passed, 0 failed)
```

## 8. Useful command groups

| Area | Commands |
|---|---|
| Membership | `register_member`, `view_member`, `member_nonce` |
| Books/copies | `register_book`, `view_book`, `add_copy`, `view_copy`, `mark_lost` |
| Lending | `borrow_book`, `return_book`, `renew_book`, `reserve_book`, `reservation_status` |
| Fines | `check_overdue`, `view_fines`, `settle_fine` |
| Tokens | `token_transfer`, `token_balance`, `utxo_view`, `account_balance`, `account_transfer`, `account_nonce`, `transaction_history <id>` |
| Chain / mining | `pool_view`, `mine_solo`, `mine_pool`, `mine_cloud <rounds>`, `chain_view`, `validate_chain`, `chain_save`, `chain_load`, `difficulty_status` |
| Fraud / audit | `fraud_review`, `approve_suspicious <id>`, `reject_suspicious <id>`, `lending_history`, `member_history`, `book_history` |
| Simulation helpers | `advance_time <days>`, `set_date YYYY-MM-DD`, `config [key value]`, `simulate_tamper <block>`, `utxo_selftest` |

Optional arguments on lending commands: `rid=ID` (force a request id, used to demonstrate the duplicate heuristic),
`nonce=N` (force a nonce, used to demonstrate replay rejection), `cond=WORN reason=CODE` on `return_book`.

## 9. Files

```
src/            C sources (crypto, registry, chain, ledger, pool, mining, persist, main)
tests/          run_tests.sh + results.txt
demo/           demo_commands.txt, DEMO_SCRIPT.md, sample_demo_output.txt
docs/           TECHNICAL_REPORT.md, SYSTEM_DESIGN.md, REQUIREMENTS_CHECKLIST.md
chain.dat       saved chain/state (text .dat)         wallet.dat   private keys (mode 0600)
```

> `wallet.dat` holds simulated wallets for every member. Never commit it (see `.gitignore`).
