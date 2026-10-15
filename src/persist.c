/*
 * persist.c - disk persistence.
 *
 * Format: plain-text structured ".dat" file, one record per line, fields
 * separated by '|' (the '|' character is rejected by input validation so
 * it can never appear inside a field). Line tags:
 *
 *   LIBCHAIN|1                      file magic + version
 *   CFG|...                         difficulty, reward, batch, loan..., clock offset, counters
 *   BOOK|MEMBER|COPY|QUEUE          registries and reservation queues
 *   BLOCK|... then REC|... x n and TX|... x m   (a block with its records / token txs)
 *   POOL|... then one REC| or TX|   a pending-pool request
 *   ACCT|... then LOG|... x k       account balance, nonce and linked-list history
 *   UTXO|...                        one output of the UTXO set
 *   END                             completeness marker
 *
 * Private keys live in a separate wallet.dat (mode 0600): WALLET|id|priv.
 * The file is written to chain.dat.tmp and atomically renamed.
 */
#include <unistd.h>
#include <sys/stat.h>
#include "libchain.h"

#define STATE_FILE  "chain.dat"
#define WALLET_FILE "wallet.dat"

int state_exists(void) { return access(STATE_FILE, F_OK) == 0; }

/* ------------------------------ writing ------------------------------ */
static void w_rec(FILE *f, const Record *r) {
    fprintf(f, "REC|%s|%s|%s|%s|%s|%s|%d|%ld|%d|%lu|%ld|%d|%s|%s|%s|%s\n", r->record_id, r->book_id, r->copy_id, r->book_title,
            r->member_id, r->member_name, r->action, (long)r->due_date, r->fine_amount, r->nonce, (long)r->timestamp,
            r->condition, r->reason, r->signer_id, r->signer_pub, r->signature);
}

static void w_tx(FILE *f, const TokenTx *t) {
    fprintf(f, "TX|%s|%d|%s|%s|%d|%d|%lu|%ld|%s|%s|%s\n", t->tx_id, t->kind, t->from, t->to, t->amount, t->fee,
            t->nonce, (long)t->timestamp, t->memo, t->signer_pub, t->signature);
}

int state_save(void) {
    FILE *f = fopen(STATE_FILE ".tmp", "w");
    if (!f) { printf("ERROR: cannot write %s\n", STATE_FILE); return -1; }
    fprintf(f, "LIBCHAIN|1\n");
    fprintf(f, "CFG|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%ld|%lu|%lu\n", cfg.difficulty, cfg.block_reward, cfg.batch_size,
            cfg.loan_days, cfg.renew_days, cfg.max_renewals, cfg.max_borrows, cfg.fine_per_day, cfg.tx_fee,
            cfg.pool_fee_pct, cfg.cloud_fee, cfg.offer_days, cfg.model, cfg.clock_offset, cfg.rid_counter, cfg.tx_counter);
    for (int i = 0; i < n_books; i++) fprintf(f, "BOOK|%s|%s|%s\n", books[i].id, books[i].title, books[i].author);
    for (int i = 0; i < n_members; i++)
        fprintf(f, "MEMBER|%s|%s|%s|%s|%lu|%d\n", members[i].id, members[i].name, members[i].course, members[i].pub, members[i].lend_nonce, members[i].fines_due);
    for (int i = 0; i < n_copies; i++) {
        Copy *c = &copies[i];
        fprintf(f, "COPY|%s|%s|%d|%d|%s|%ld|%d|%d|%s\n", c->id, c->book_id, c->condition, c->state, c->holder, (long)c->due_date,
                c->renew_count, c->fine_charged, c->lost_reason);
    }
    for (int i = 0; i < n_queue; i++) fprintf(f, "QUEUE|%s|%s|%ld\n", queue[i].book_id, queue[i].member_id, (long)queue[i].date);
    for (int i = 0; i < chain_len; i++) {
        Block *b = &chain[i];
        fprintf(f, "BLOCK|%d|%ld|%d|%s|%s|%s|%s|%d|%s|%lu|%d|%d\n", b->index, (long)b->timestamp, b->record_count, b->previous_hash,
                b->merkle_root, b->hash, b->sealed_by, b->token_reward, b->transaction_id, b->nonce, b->difficulty, b->tx_count);
        for (int j = 0; j < b->record_count; j++) w_rec(f, &b->records[j]);
        for (int j = 0; j < b->tx_count; j++) w_tx(f, &b->txs[j]);
    }
    for (int i = 0; i < n_pool; i++) {
        PoolItem *p = &pool[i];
        fprintf(f, "POOL|%s|%d|%d|%ld|%d|%d|%s\n", p->request_id, p->kind, p->priority, (long)p->req_date, p->status, p->approved, p->reason);
        if (p->kind == KIND_LENDING) w_rec(f, &p->rec); else w_tx(f, &p->tx);
    }
    for (int i = 0; i < n_accounts; i++) {
        Account *a = &accounts[i];
        fprintf(f, "ACCT|%s|%d|%lu\n", a->id, a->balance, a->nonce);
        for (TxLog *e = a->head; e; e = e->next)
            fprintf(f, "LOG|%s|%s|%d|%d|%lu|%d|%s\n", e->sender, e->recipient, e->amount, e->fee, e->nonce, e->block, e->kind);
    }
    for (int i = 0; i < n_utxos; i++)
        fprintf(f, "UTXO|%s|%d|%s|%d|%d\n", utxos[i].txid, utxos[i].index, utxos[i].owner, utxos[i].amount, utxos[i].spent);
    fprintf(f, "END\n");
    if (fclose(f) != 0 || rename(STATE_FILE ".tmp", STATE_FILE) != 0) { printf("ERROR: could not finalise %s\n", STATE_FILE); return -1; }
    wallet_save();
    return 0;
}

void wallet_save(void) {
    FILE *f = fopen(WALLET_FILE, "w");
    if (!f) return;
    chmod(WALLET_FILE, 0600);
    for (int i = 0; i < n_members; i++) if (members[i].priv[0]) fprintf(f, "WALLET|%s|%s\n", members[i].id, members[i].priv);
    fclose(f);
}

/* ------------------------------ reading ------------------------------ */
/* Split on '|' keeping empty fields. */
static int split(char *line, char *f[], int max) {
    int n = 0; char *p = line;
    while (n < max) {
        f[n++] = p;
        char *c = strchr(p, '|');
        if (!c) break;
        *c = '\0'; p = c + 1;
    }
    return n;
}
static long L(const char *s) { return strtol(s, NULL, 10); }
static unsigned long U(const char *s) { return strtoul(s, NULL, 10); }

static int r_rec(char **f, int n, Record *r) {
    if (n < 17) return -1;
    memset(r, 0, sizeof *r);
    scpy(r->record_id, sizeof r->record_id, f[1]); scpy(r->book_id, sizeof r->book_id, f[2]); scpy(r->copy_id, sizeof r->copy_id, f[3]);
    scpy(r->book_title, sizeof r->book_title, f[4]); scpy(r->member_id, sizeof r->member_id, f[5]); scpy(r->member_name, sizeof r->member_name, f[6]);
    r->action = (int)L(f[7]); r->due_date = (time_t)L(f[8]); r->fine_amount = (int)L(f[9]); r->nonce = U(f[10]); r->timestamp = (time_t)L(f[11]);
    r->condition = (int)L(f[12]); scpy(r->reason, sizeof r->reason, f[13]); scpy(r->signer_id, sizeof r->signer_id, f[14]);
    scpy(r->signer_pub, sizeof r->signer_pub, f[15]); scpy(r->signature, sizeof r->signature, f[16]);
    if (r->action < 0 || r->action >= ACT_COUNT || r->condition < 0 || r->condition >= COND_COUNT) return -1;
    return 0;
}

static int r_tx(char **f, int n, TokenTx *t) {
    if (n < 12) return -1;
    memset(t, 0, sizeof *t);
    scpy(t->tx_id, sizeof t->tx_id, f[1]); t->kind = (int)L(f[2]); scpy(t->from, sizeof t->from, f[3]); scpy(t->to, sizeof t->to, f[4]);
    t->amount = (int)L(f[5]); t->fee = (int)L(f[6]); t->nonce = U(f[7]); t->timestamp = (time_t)L(f[8]);
    scpy(t->memo, sizeof t->memo, f[9]); scpy(t->signer_pub, sizeof t->signer_pub, f[10]); scpy(t->signature, sizeof t->signature, f[11]);
    return 0;
}

static void reset_state(void) {
    n_books = n_copies = n_members = n_queue = n_pool = 0;
    ledger_free(); free(chain); chain = NULL; chain_len = 0;
}

int state_load(void) {
    FILE *f = fopen(STATE_FILE, "r");
    if (!f) { printf("ERROR: no saved chain file (%s)\n", STATE_FILE); return -1; }
    reset_state();
    static char line[4096];
    char *fld[24]; int ok = 1, ended = 0, lineno = 0;
    Block *cur = NULL; int recs_read = 0, txs_read = 0; PoolItem *curp = NULL; Account *cura = NULL;
    while (fgets(line, sizeof line, f) && ok) {
        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0]) continue;
        int n = split(line, fld, 24); const char *tag = fld[0];
        if (!strcmp(tag, "LIBCHAIN")) { if (n < 2 || L(fld[1]) != 1) ok = 0; }
        else if (!strcmp(tag, "CFG") && n >= 17) {
            cfg.difficulty = (int)L(fld[1]); cfg.block_reward = (int)L(fld[2]); cfg.batch_size = (int)L(fld[3]); cfg.loan_days = (int)L(fld[4]);
            cfg.renew_days = (int)L(fld[5]); cfg.max_renewals = (int)L(fld[6]); cfg.max_borrows = (int)L(fld[7]); cfg.fine_per_day = (int)L(fld[8]);
            cfg.tx_fee = (int)L(fld[9]); cfg.pool_fee_pct = (int)L(fld[10]); cfg.cloud_fee = (int)L(fld[11]); cfg.offer_days = (int)L(fld[12]);
            cfg.model = (int)L(fld[13]); cfg.clock_offset = L(fld[14]); cfg.rid_counter = U(fld[15]); cfg.tx_counter = U(fld[16]);
        }
        else if (!strcmp(tag, "BOOK") && n >= 4 && n_books < MAX_BOOKS) {
            Book *b = &books[n_books++]; scpy(b->id, sizeof b->id, fld[1]); scpy(b->title, sizeof b->title, fld[2]); scpy(b->author, sizeof b->author, fld[3]);
        }
        else if (!strcmp(tag, "MEMBER") && n >= 7 && n_members < MAX_MEMBERS) {
            Member *m = &members[n_members++]; memset(m, 0, sizeof *m);
            scpy(m->id, sizeof m->id, fld[1]); scpy(m->name, sizeof m->name, fld[2]); scpy(m->course, sizeof m->course, fld[3]);
            scpy(m->pub, sizeof m->pub, fld[4]); m->lend_nonce = U(fld[5]); m->fines_due = (int)L(fld[6]);
        }
        else if (!strcmp(tag, "COPY") && n >= 10 && n_copies < MAX_COPIES) {
            Copy *c = &copies[n_copies++]; memset(c, 0, sizeof *c);
            scpy(c->id, sizeof c->id, fld[1]); scpy(c->book_id, sizeof c->book_id, fld[2]); c->condition = (int)L(fld[3]); c->state = (int)L(fld[4]);
            scpy(c->holder, sizeof c->holder, fld[5]); c->due_date = (time_t)L(fld[6]); c->renew_count = (int)L(fld[7]);
            c->fine_charged = (int)L(fld[8]); scpy(c->lost_reason, sizeof c->lost_reason, fld[9]);
            if (c->condition < 0 || c->condition >= COND_COUNT || c->state < 0 || c->state >= ST_COUNT) ok = 0;
        }
        else if (!strcmp(tag, "QUEUE") && n >= 4) queue_push(fld[1], fld[2], (time_t)L(fld[3]));
        else if (!strcmp(tag, "BLOCK") && n >= 13) {
            chain = realloc(chain, (size_t)(chain_len + 1) * sizeof(Block));
            cur = &chain[chain_len++]; memset(cur, 0, sizeof *cur); curp = NULL;
            cur->index = (int)L(fld[1]); cur->timestamp = (time_t)L(fld[2]); cur->record_count = (int)L(fld[3]);
            scpy(cur->previous_hash, sizeof cur->previous_hash, fld[4]); scpy(cur->merkle_root, sizeof cur->merkle_root, fld[5]);
            scpy(cur->hash, sizeof cur->hash, fld[6]); scpy(cur->sealed_by, sizeof cur->sealed_by, fld[7]);
            cur->token_reward = (int)L(fld[8]); scpy(cur->transaction_id, sizeof cur->transaction_id, fld[9]);
            cur->nonce = U(fld[10]); cur->difficulty = (int)L(fld[11]); cur->tx_count = (int)L(fld[12]);
            if (cur->record_count < 0 || cur->record_count > MAX_RECS || cur->tx_count < 0 || cur->tx_count > MAX_TXS) ok = 0;
            recs_read = txs_read = 0;
        }
        else if (!strcmp(tag, "POOL") && n >= 8 && n_pool < MAX_POOL) {
            curp = &pool[n_pool++]; memset(curp, 0, sizeof *curp); cur = NULL;
            scpy(curp->request_id, sizeof curp->request_id, fld[1]); curp->kind = (int)L(fld[2]); curp->priority = (int)L(fld[3]);
            curp->req_date = (time_t)L(fld[4]); curp->status = (int)L(fld[5]); curp->approved = (int)L(fld[6]); scpy(curp->reason, sizeof curp->reason, fld[7]);
        }
        else if (!strcmp(tag, "REC")) {
            Record r;
            if (r_rec(fld, n, &r)) ok = 0;
            else if (cur && recs_read < cur->record_count) cur->records[recs_read++] = r;
            else if (curp && curp->kind == KIND_LENDING) curp->rec = r;
            else ok = 0;
        }
        else if (!strcmp(tag, "TX")) {
            TokenTx t;
            if (r_tx(fld, n, &t)) ok = 0;
            else if (cur && txs_read < cur->tx_count) cur->txs[txs_read++] = t;
            else if (curp && curp->kind == KIND_TRANSFER) curp->tx = t;
            else ok = 0;
        }
        else if (!strcmp(tag, "ACCT") && n >= 4) { cura = acct_get(fld[1], 1); if (cura) { cura->balance = (int)L(fld[2]); cura->nonce = U(fld[3]); } }
        else if (!strcmp(tag, "LOG") && n >= 8 && cura) {
            TxLog *e = calloc(1, sizeof *e);
            if (!e) { ok = 0; break; }
            scpy(e->sender, sizeof e->sender, fld[1]); scpy(e->recipient, sizeof e->recipient, fld[2]); e->amount = (int)L(fld[3]); e->fee = (int)L(fld[4]);
            e->nonce = U(fld[5]); e->block = (int)L(fld[6]); scpy(e->kind, sizeof e->kind, fld[7]);
            if (cura->tail) cura->tail->next = e; else cura->head = e;
            cura->tail = e;
        }
        else if (!strcmp(tag, "UTXO") && n >= 6 && n_utxos < MAX_UTXOS) {
            Utxo *u = &utxos[n_utxos++]; scpy(u->txid, sizeof u->txid, fld[1]); u->index = (int)L(fld[2]);
            scpy(u->owner, sizeof u->owner, fld[3]); u->amount = (int)L(fld[4]); u->spent = (int)L(fld[5]);
        }
        else if (!strcmp(tag, "END")) { ended = 1; break; }
        else { printf("ERROR: %s line %d: unrecognised or malformed line '%.12s'\n", STATE_FILE, lineno, tag); ok = 0; }
    }
    fclose(f);
    if (!ok || !ended || chain_len < 1) { printf("ERROR: %s is corrupt or incomplete - state not loaded.\n", STATE_FILE); return -1; }

    FILE *w = fopen(WALLET_FILE, "r");                       /* private keys */
    if (!w) printf("WARNING: %s missing - existing members cannot sign new requests.\n", WALLET_FILE);
    else {
        while (fgets(line, sizeof line, w)) {
            line[strcspn(line, "\r\n")] = '\0';
            int n = split(line, fld, 4);
            if (n >= 3 && !strcmp(fld[0], "WALLET")) { int mi = find_member(fld[1]); if (mi >= 0) scpy(members[mi].priv, sizeof members[mi].priv, fld[2]); }
        }
        fclose(w);
    }
    return 0;
}
