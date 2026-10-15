#!/bin/bash
# Automated scenario tests. Usage: ./tests/run_tests.sh   (from project root, after `make`)
# Each scenario runs in a fresh temp dir; every check compares EXPECTED text with the ACTUAL program output.
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PASS=0; FAIL=0
newdir() { D=$(mktemp -d); for f in books.txt copies.txt members.txt libchain; do cp "$ROOT/$f" "$D/"; done; cd "$D" || exit 1; }
check() {  # check <description> <expected fixed string> <output>
  if grep -qF -- "$2" <<<"$3"; then PASS=$((PASS+1)); printf '  [PASS] %s\n         expected: %s\n         actual  : %s\n' "$1" "$2" "$(grep -F -- "$2" <<<"$3" | head -1 | cut -c1-110)";
  else FAIL=$((FAIL+1)); printf '  [FAIL] %s\n         expected: %s\n         actual  : (not found)\n' "$1" "$2"; fi
}

echo "=== Scenario 1: registry validation, borrow, PoW mining, chain validation"
newdir
OUT=$(printf 'borrow_book M001 B001\nborrow_book M001 B999\nborrow_book M099 B001\nmine_solo\nvalidate_chain\n' | ./libchain --difficulty 2 2>&1)
check "valid borrow signed and pooled" "ECDSA) and added to pending pool [PENDING]" "$OUT"
check "unknown book rejected"          "book id 'B999' is invalid or not in the book registry" "$OUT"
check "unknown member rejected"        "member id 'M099' is invalid or not in the member registry" "$OUT"
check "block mined at difficulty 2"    "CONFIRMED block 1  hash=00" "$OUT"
check "hash attempts displayed"        "hash attempts=" "$OUT"
check "chain validates"                "CHAIN VALID: 2 block(s) verified" "$OUT"

echo "=== Scenario 2: reservation queue, automatic offer, token rewards (on-time 10, late 5)"
newdir
OUT=$(printf 'borrow_book M001 B002\nborrow_book M002 B003\nmine_solo\nreserve_book M003 B002\nmine_solo\nreturn_book M001 C003\nmine_solo\nview_copy C003\nadvance_time 20\nreturn_book M002 C004\nmine_solo\ntoken_balance M001\ntoken_balance M002\nset_model account\naccount_balance M002\n' | ./libchain 2>&1)
check "reservation joins queue"        "M003 joined the reservation queue for B002 (position 1)" "$OUT"
check "auto offer on return"           "automatically OFFERED to M003" "$OUT"
check "copy state RESERVED for M003"   "state=RESERVED  holder=M003" "$OUT"
check "on-time reward 10 (UTXO)"       "M001 balance: 10 coins  [model: UTXO]" "$OUT"
check "late reward 5 (UTXO)"           "M002 balance: 5 coins  [model: UTXO]" "$OUT"
check "account model agrees"           "Account M002: balance=5 nonce=0" "$OUT"

echo "=== Scenario 3: overdue detection, prioritisation, fines, settlement"
newdir
OUT=$(printf 'borrow_book M001 B001\nborrow_book M002 B002\nmine_solo\nadvance_time 15\nborrow_book M003 B003\nreturn_book M001 C001\npool_view\nmine_solo\nview_fines\nset_model account\nsettle_fine M001\npool_view\nmine_solo\nview_fines M001\n' | ./libchain 2>&1)
check "overdue scan flags copies"      "is 1 day(s) overdue -> fine accrued 1" "$OUT"
check "late return fine computed"      "Return is LATE by 1 day(s): fine_amount=1" "$OUT"
check "overdue request has priority 0" "OVERDUE   B001   C001   M001    0" "$OUT"
check "fine booked on member"          "M001   Alice Uwase            fines_due=1" "$OUT"
check "fine settlement queued"         "TRANSFER M001 -> LIBRARY amount=1 fee=1" "$OUT"
check "fine settled"                   "M001 settled fines worth 1 coin(s)" "$OUT"

echo "=== Scenario 4: fraud heuristics and review workflow"
newdir
OUT=$(printf 'config max_borrows 1\nborrow_book M001 B001\nborrow_book M001 B002\nborrow_book M002 B003 rid=R0001\nfraud_review\nmine_solo\nreject_suspicious R0002\napprove_suspicious R0001\npool_view\n' | ./libchain 2>&1)
check "concurrent-borrow flag"         "excessive concurrent borrows (limit 1)" "$OUT"
check "duplicate-id flag"              "duplicate request_id" "$OUT"
check "suspicious listed for review"   "Fraud review queue" "$OUT"
check "reject discards request"        "Request R0002 rejected and discarded" "$OUT"
check "approve releases request"       "Request R0001 approved by librarian" "$OUT"
check "unflagged request mined first (suspicious withheld)" "Block 1 planned: 1 request(s)" "$OUT"

echo "=== Scenario 5: tamper detection and persistence across restarts"
newdir
printf 'borrow_book M001 B001\nmine_solo\n' | ./libchain >/dev/null 2>&1
OUT=$(printf 'borrow_book M002 B002\nvalidate_chain\nborrow_book M002 B002\nmine_solo\nsimulate_tamper 1\nvalidate_chain\nchain_load\nvalidate_chain\n' | ./libchain 2>&1)
check "restart restores chain"         "Saved chain found: restored 2 block(s)" "$OUT"
check "ops locked before validation"   "LOCKED:" "$OUT"
check "tamper -> Merkle mismatch"      "Merkle root mismatch" "$OUT"
check "tamper -> signature failure"    "invalid ECDSA signature" "$OUT"
check "chain_load restores clean chain" "CHAIN VALID" "$OUT"
sed -i '0,/^REC|R0001|B001|C001|Introduction to Algorithms|M001|Alice Uwase|0|[0-9]*|0|/s//REC|R0001|B001|C001|Introduction to Algorithms|M001|Alice Uwase|0|9999999999|0|/' chain.dat
OUT=$(./libchain validate_chain 2>&1)
check "on-disk edit detected"          "CHAIN INVALID" "$OUT"

echo "=== Scenario 6: solo / pool / cloud mining"
newdir
OUT=$(printf 'borrow_book M001 B001\nmine_solo\nborrow_book M002 B002\nmine_pool\nborrow_book M003 B003\nmine_cloud 5\nborrow_book M004 B004\nconfig cloud_fee 200\nmine_cloud 5\nmine_cloud 9\ndifficulty_status\nset_difficulty 7\n' | ./libchain --difficulty 3 2>&1)
check "solo full reward"               "SOLO mining reward: 100 coins" "$OUT"
check "pool table header"              "| Miner ID | Hash rate | Attempts | Share %   | Reward   |" "$OUT"
check "pool fee 2%"                    "pool fee 2% = 2, distributable 98" "$OUT"
check "cloud earnings summary"         "Gross earnings:" "$OUT"
check "cloud warning when fees > rewards" "WARNING: cumulative fees" "$OUT"
check "rental > 5 rounds rejected"     "rental duration must be 1 to 5 rounds" "$OUT"
check "difficulty range enforced"      "difficulty must be 1..4" "$OUT"

echo "=== Scenario 7: replay protection, insufficient funds, UTXO fee/change, double spend"
newdir
OUT=$(printf 'borrow_book M001 B001\nmine_solo\nreturn_book M001 C001\nmine_solo\nborrow_book M001 B001 nonce=0\ntoken_transfer M001 M002 500\naccount_transfer M001 M002 3 nonce=9\ntoken_transfer M001 M002 3\nmine_solo\nutxo_view\nutxo_selftest\naccount_balance M001\ntransaction_history M001\n' | ./libchain 2>&1)
check "lending nonce replay rejected"  "replay protection - nonce 0 rejected" "$OUT"
check "insufficient balance rejected"  "insufficient balance" "$OUT"
check "bad account nonce rejected"     "account nonce 9 rejected" "$OUT"
check "fee charged, change returned"   "M001           6" "$OUT"
check "double-spend prevented"         "double-spend prevented" "$OUT"
check "history linked list"            "TRANSFER  M001" "$OUT"

echo; echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
