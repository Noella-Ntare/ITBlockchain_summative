/*
 * chain.c - lending records, Merkle tree, block hashing, chain validation
 * and read-only history queries.
 */
#include "libchain.h"

Block *chain; int chain_len;

/* ------------------------------------------------------------------ */
/* Records                                                              */
/* ------------------------------------------------------------------ */
/* Canonical text form of a record: this exact string is what gets hashed
 * and signed. Any change to any field changes the digest. */
void record_canonical(const Record *r, char *buf, size_t n, int with_sig) {
    int k = snprintf(buf, n, "%s|%s|%s|%s|%s|%s|%s|%ld|%d|%lu|%ld|%s|%s|%s|%s",
                     r->record_id, r->book_id, r->copy_id, r->book_title, r->member_id, r->member_name,
                     ACTION_NAMES[r->action], (long)r->due_date, r->fine_amount, r->nonce, (long)r->timestamp,
                     COND_NAMES[r->condition], r->reason, r->signer_id, r->signer_pub);
    if (with_sig && k > 0 && (size_t)k < n) snprintf(buf + k, n - (size_t)k, "|%s", r->signature);
}

int record_sign(Record *r, const char *priv) {
    char buf[1400];
    record_canonical(r, buf, sizeof buf, 0);
    return crypto_sign(priv, buf, r->signature, sizeof r->signature);
}

int record_verify(const Record *r) {
    char buf[1400];
    if (r->action < 0 || r->action >= ACT_COUNT || r->condition < 0 || r->condition >= COND_COUNT) return 0;
    record_canonical(r, buf, sizeof buf, 0);
    return crypto_verify(r->signer_pub, buf, r->signature);
}

/* Merkle leaf = SHA-256 of the full record including its signature. */
void record_leaf(const Record *r, char out[HASH_LEN]) {
    char buf[1600];
    record_canonical(r, buf, sizeof buf, 1);
    sha256_hex(buf, strlen(buf), out);
}

/*
 * Merkle tree built from scratch: leaves are record hashes; each parent is
 * SHA-256(left_hex || right_hex); an odd node is paired with itself.
 */
void merkle_root(const Record *recs, int n, char out[HASH_LEN]) {
    char level[MAX_RECS][HASH_LEN];
    if (n <= 0) { sha256_hex("EMPTY", 5, out); return; }
    for (int i = 0; i < n; i++) record_leaf(&recs[i], level[i]);
    int cnt = n;
    while (cnt > 1) {
        int next = 0;
        for (int i = 0; i < cnt; i += 2) {
            char pair[2 * (HASH_LEN - 1) + 1];                 /* left_hex || right_hex */
            int ri = (i + 1 < cnt) ? i + 1 : i;                /* odd node pairs with itself */
            memcpy(pair, level[i], HASH_LEN - 1);
            memcpy(pair + HASH_LEN - 1, level[ri], HASH_LEN - 1);
            pair[2 * (HASH_LEN - 1)] = '\0';
            sha256_hex(pair, strlen(pair), level[next++]);
        }
        cnt = next;
    }
    memcpy(out, level[0], HASH_LEN);
}

/* ------------------------------------------------------------------ */
/* Token transactions                                                   */
/* ------------------------------------------------------------------ */
void tx_canonical(const TokenTx *t, char *buf, size_t n) {
    snprintf(buf, n, "TX|%d|%s|%s|%d|%d|%lu|%ld|%s|%s", t->kind, t->from, t->to, t->amount, t->fee,
             t->nonce, (long)t->timestamp, t->memo, t->signer_pub);
}

/* System-issued reward (coinbase-style): no signer, id derived from content. */
void tx_make_reward(TokenTx *t, const char *to, int amount, const char *memo, time_t ts) {
    char buf[512];
    memset(t, 0, sizeof *t);
    t->kind = TX_REWARD; scpy(t->from, sizeof t->from, "SYSTEM"); scpy(t->to, sizeof t->to, to);
    t->amount = amount; t->fee = 0; t->nonce = 0; t->timestamp = ts; scpy(t->memo, sizeof t->memo, memo);
    tx_canonical(t, buf, sizeof buf);
    sha256_hex(buf, strlen(buf), t->tx_id);
}

int tx_sign(TokenTx *t, const char *priv) {
    char buf[512], full[800];
    tx_canonical(t, buf, sizeof buf);
    if (crypto_sign(priv, buf, t->signature, sizeof t->signature)) return -1;
    snprintf(full, sizeof full, "%s|%s", buf, t->signature);
    sha256_hex(full, strlen(full), t->tx_id);
    return 0;
}

int tx_verify(const TokenTx *t) {
    char buf[512];
    tx_canonical(t, buf, sizeof buf);
    return crypto_verify(t->signer_pub, buf, t->signature);
}

/* transaction_id of a block = SHA-256 over the concatenated tx ids. */
static void block_txid(const Block *b, char out[HASH_LEN]) {
    char buf[MAX_TXS * HASH_LEN + 8]; buf[0] = '\0';
    if (b->tx_count == 0) { sha256_hex("NOTX", 4, out); return; }
    for (int i = 0; i < b->tx_count; i++) strcat(buf, b->txs[i].tx_id);
    sha256_hex(buf, strlen(buf), out);
}

/* Fill token_reward and transaction_id from the block's tx list. */
void block_finalize_tx(Block *b) {
    b->token_reward = 0;
    for (int i = 0; i < b->tx_count; i++) if (b->txs[i].kind == TX_REWARD) b->token_reward += b->txs[i].amount;
    block_txid(b, b->transaction_id);
}

/* ------------------------------------------------------------------ */
/* Blocks                                                               */
/* ------------------------------------------------------------------ */
void block_hash(const Block *b, char out[HASH_LEN]) {
    char buf[600];
    snprintf(buf, sizeof buf, "%d|%ld|%d|%s|%s|%s|%d|%s|%d|%lu", b->index, (long)b->timestamp, b->record_count,
             b->previous_hash, b->merkle_root, b->sealed_by, b->token_reward, b->transaction_id,
             b->difficulty, b->nonce);
    sha256_hex(buf, strlen(buf), out);
}

/* Proof-of-work test: hash must begin with `difficulty` hex zeros. */
int pow_ok(const char *hash, int difficulty) {
    for (int i = 0; i < difficulty; i++) if (hash[i] != '0') return 0;
    return 1;
}

void chain_init_genesis(void) {
    free(chain);
    chain = calloc(1, sizeof(Block));
    chain_len = 1;
    Block *g = &chain[0];
    g->index = 0; g->timestamp = sim_now(); g->record_count = 0;
    scpy(g->previous_hash, sizeof g->previous_hash, ZERO_HASH);
    merkle_root(NULL, 0, g->merkle_root);
    scpy(g->sealed_by, sizeof g->sealed_by, "GENESIS");
    g->tx_count = 0; block_finalize_tx(g);
    g->difficulty = 0; g->nonce = 0;
    block_hash(g, g->hash);
}

void chain_append(const Block *b) {
    chain = realloc(chain, (size_t)(chain_len + 1) * sizeof(Block));
    chain[chain_len++] = *b;
}

/* ------------------------------------------------------------------ */
/* Lookup helpers used by lending logic                                  */
/* ------------------------------------------------------------------ */
const Record *find_last_borrowed(const char *copy_id) {
    for (int i = chain_len - 1; i >= 0; i--)
        for (int j = chain[i].record_count - 1; j >= 0; j--)
            if (chain[i].records[j].action == ACT_BORROWED && !strcmp(chain[i].records[j].copy_id, copy_id))
                return &chain[i].records[j];
    return NULL;
}

int chain_has_record_id(const char *rid) {
    for (int i = 0; i < chain_len; i++)
        for (int j = 0; j < chain[i].record_count; j++)
            if (!strcmp(chain[i].records[j].record_id, rid)) return 1;
    return 0;
}

/* Did this member return a copy of this title at or after `since`? */
int chain_recent_return(const char *member_id, const char *book_id, time_t since) {
    for (int i = chain_len - 1; i >= 0; i--)
        for (int j = chain[i].record_count - 1; j >= 0; j--) {
            const Record *r = &chain[i].records[j];
            if (r->action == ACT_RETURNED && r->timestamp >= since &&
                !strcmp(r->member_id, member_id) && !strcmp(r->book_id, book_id)) return 1;
        }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Full chain validation / tamper detection                             */
/* ------------------------------------------------------------------ */
static int vfail(int verbose, int *errs, const char *fmt, int blk, const char *detail) {
    (*errs)++;
    if (verbose) { printf("  [FAIL] block %d: ", blk); printf(fmt, detail); printf("\n"); }
    return 0;
}

/*
 * Checks, for every block: index, previous-hash linkage, block hash,
 * proof of work, Merkle root, strictly increasing timestamps, and for
 * every record: ECDSA signature, signer identity = registered public key,
 * referential integrity with the registries, per-signer nonce order;
 * for every token tx: id, signature (transfers), block transaction_id
 * and token_reward. Returns 1 if the whole chain is valid.
 */
int validate_chain(int verbose) {
    int errs = 0;
    unsigned long exp_nonce[MAX_MEMBERS]; unsigned long exp_tx[MAX_MEMBERS];
    memset(exp_nonce, 0, sizeof exp_nonce); memset(exp_tx, 0, sizeof exp_tx);
    if (chain_len < 1) { if (verbose) printf("  [FAIL] chain is empty\n"); return 0; }
    for (int i = 0; i < chain_len; i++) {
        Block *b = &chain[i]; char h[HASH_LEN]; int before = errs;
        if (b->index != i) vfail(verbose, &errs, "index mismatch (%s)", i, "stored index differs from position");
        if (i == 0) { if (strcmp(b->previous_hash, ZERO_HASH)) vfail(verbose, &errs, "genesis previous_hash (%s)", i, "not all zeros"); }
        else {
            if (strcmp(b->previous_hash, chain[i - 1].hash)) vfail(verbose, &errs, "previous-hash linkage broken (%s)", i, "does not match previous block hash");
            if (b->timestamp <= chain[i - 1].timestamp) vfail(verbose, &errs, "timestamp not strictly increasing (%s)", i, "<= previous block");
            if (b->difficulty < 1 || b->difficulty > 4) vfail(verbose, &errs, "difficulty out of range (%s)", i, "must be 1..4");
        }
        block_hash(b, h);
        if (strcmp(h, b->hash)) vfail(verbose, &errs, "stored hash != recomputed hash (%s)", i, "block contents modified");
        if (i > 0 && !pow_ok(b->hash, b->difficulty)) vfail(verbose, &errs, "proof-of-work invalid (%s)", i, "hash lacks required leading zeros");
        merkle_root(b->records, b->record_count, h);
        if (strcmp(h, b->merkle_root)) vfail(verbose, &errs, "Merkle root mismatch (%s)", i, "a record was modified");
        if (b->record_count < 0 || b->record_count > MAX_RECS || b->tx_count < 0 || b->tx_count > MAX_TXS) {
            vfail(verbose, &errs, "bad record/tx count (%s)", i, ""); continue;
        }
        int reward_sum = 0;
        for (int j = 0; j < b->record_count; j++) {
            const Record *r = &b->records[j];
            if (!record_verify(r)) vfail(verbose, &errs, "invalid ECDSA signature (%s)", i, r->record_id);
            int si = find_member(r->signer_id), mi = find_member(r->member_id), bi = find_book(r->book_id);
            if (si < 0 || strcmp(members[si].pub, r->signer_pub)) vfail(verbose, &errs, "signer key not the registered key (%s)", i, r->record_id);
            if (mi < 0) vfail(verbose, &errs, "member_id not in registry (%s)", i, r->record_id);
            else if (strcmp(members[mi].name, r->member_name)) vfail(verbose, &errs, "member_name differs from registry (%s)", i, r->record_id);
            if (bi < 0) vfail(verbose, &errs, "book_id not in registry (%s)", i, r->record_id);
            else if (strcmp(books[bi].title, r->book_title)) vfail(verbose, &errs, "book_title differs from registry (%s)", i, r->record_id);
            if (strcmp(r->copy_id, "-")) {
                int ci = find_copy(r->copy_id);
                if (ci < 0 || strcmp(copies[ci].book_id, r->book_id)) vfail(verbose, &errs, "copy_id invalid for book (%s)", i, r->record_id);
            }
            if (r->fine_amount < 0) vfail(verbose, &errs, "negative fine (%s)", i, r->record_id);
            if (si >= 0) {
                if (r->nonce != exp_nonce[si]) vfail(verbose, &errs, "nonce out of order / replayed (%s)", i, r->record_id);
                exp_nonce[si] = r->nonce + 1;
            }
            if (r->action == ACT_RETURNED) reward_sum += (r->timestamp > r->due_date) ? 5 : 10;
        }
        int tok = 0;
        for (int j = 0; j < b->tx_count; j++) {
            const TokenTx *t = &b->txs[j];
            if (t->kind == TX_REWARD) tok += t->amount;
            else {
                if (!tx_verify(t)) vfail(verbose, &errs, "invalid transfer signature (%s)", i, t->tx_id);
                int fi = find_member(t->from);
                if (fi < 0 || strcmp(members[fi].pub, t->signer_pub)) vfail(verbose, &errs, "transfer signer key mismatch (%s)", i, t->tx_id);
                else { if (t->nonce != exp_tx[fi]) vfail(verbose, &errs, "transfer nonce out of order (%s)", i, t->tx_id); exp_tx[fi] = t->nonce + 1; }
                if (t->amount < 0 || t->fee < 0) vfail(verbose, &errs, "negative token amount (%s)", i, t->tx_id);
            }
        }
        if (tok != b->token_reward || tok != reward_sum) vfail(verbose, &errs, "token_reward inconsistent with returns (%s)", i, "");
        block_txid(b, h);
        if (strcmp(h, b->transaction_id)) vfail(verbose, &errs, "transaction_id mismatch (%s)", i, "token txs modified");
        if (verbose && errs == before) printf("  [ OK ] block %d  hash=%.16s...  records=%d  txs=%d\n", i, b->hash, b->record_count, b->tx_count);
    }
    if (verbose) {
        if (errs) printf("CHAIN INVALID: %d problem(s) detected.\n", errs);
        else printf("CHAIN VALID: %d block(s) verified (links, hashes, PoW, Merkle roots, ECDSA signatures, nonces).\n", chain_len);
    }
    return errs == 0;
}

/* ------------------------------------------------------------------ */
/* Views / audit queries                                                */
/* ------------------------------------------------------------------ */
void cmd_chain_view(int last_n) {
    int start = (last_n > 0 && last_n < chain_len) ? chain_len - last_n : 0;
    for (int i = start; i < chain_len; i++) {
        Block *b = &chain[i]; char d[24]; fmt_datetime(b->timestamp, d);
        printf("+-- Block %d ------------------------------------------------\n", b->index);
        printf("| time      : %s   sealed_by: %s   difficulty: %d   nonce: %lu\n", d, b->sealed_by, b->difficulty, b->nonce);
        printf("| hash      : %s\n| prev_hash : %s\n| merkle    : %s\n", b->hash, b->previous_hash, b->merkle_root);
        printf("| records   : %d   token_reward: %d   transaction_id: %.16s...\n", b->record_count, b->token_reward, b->transaction_id);
        for (int j = 0; j < b->record_count; j++) {
            const Record *r = &b->records[j]; char due[24] = "-";
            if (r->due_date) fmt_date(r->due_date, due);
            printf("|   %-6s %-9s book=%-5s copy=%-5s member=%-6s due=%s fine=%d nonce=%lu sig=%.12s...\n", r->record_id,
                   ACTION_NAMES[r->action], r->book_id, r->copy_id, r->member_id, due, r->fine_amount, r->nonce, r->signature);
        }
        for (int j = 0; j < b->tx_count; j++) {
            const TokenTx *t = &b->txs[j];
            printf("|   tx %.10s %-8s %s -> %s amount=%d fee=%d %s\n", t->tx_id, t->kind == TX_REWARD ? "REWARD" : "TRANSFER",
                   t->from, t->to, t->amount, t->fee, t->memo);
        }
    }
    printf("+-- (%d block(s) on chain, tip hash %.16s...)\n", chain_len, chain[chain_len - 1].hash);
}

/* member_id / book_id filters; NULL means "all". */
void cmd_history(const char *member_id, const char *book_id) {
    int n = 0;
    printf("%-6s %-5s %-9s %-6s %-6s %-6s %-11s %-5s %s\n", "REC", "BLK", "ACTION", "BOOK", "COPY", "MEMBER", "DUE", "FINE", "TIME");
    for (int i = 0; i < chain_len; i++)
        for (int j = 0; j < chain[i].record_count; j++) {
            const Record *r = &chain[i].records[j];
            if (member_id && strcmp(r->member_id, member_id)) continue;
            if (book_id && strcmp(r->book_id, book_id)) continue;
            char due[24] = "-", ts[24]; if (r->due_date) fmt_date(r->due_date, due);
            fmt_datetime(r->timestamp, ts);
            printf("%-6s %-5d %-9s %-6s %-6s %-6s %-11s %-5d %s\n", r->record_id, i, ACTION_NAMES[r->action], r->book_id,
                   r->copy_id, r->member_id, due, r->fine_amount, ts);
            n++;
        }
    printf("(%d record(s))\n", n);
}
