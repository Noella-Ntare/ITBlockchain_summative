/*
 * ledger.c - the two token balance models required by Formative 2.
 *
 *  - Account model : balance + outgoing-nonce per account, linked-list
 *                    transaction history per account.
 *  - UTXO model    : unspent outputs with inputs/outputs, fee and change.
 *
 * Both ledgers are updated for every confirmed token transaction so they
 * always agree; cfg.model selects which one is authoritative for balance
 * checks and which view is printed after each block.
 */
#include "libchain.h"

Account accounts[MAX_ACCOUNTS]; int n_accounts;
Utxo utxos[MAX_UTXOS];          int n_utxos;

Account *acct_get(const char *id, int create) {
    for (int i = 0; i < n_accounts; i++) if (!strcmp(accounts[i].id, id)) return &accounts[i];
    if (!create || n_accounts >= MAX_ACCOUNTS) return NULL;
    Account *a = &accounts[n_accounts++];
    memset(a, 0, sizeof *a);
    scpy(a->id, sizeof a->id, id);
    return a;
}

static void log_add(Account *a, const char *sender, const char *recipient, int amount, int fee,
                    unsigned long nonce, int block, const char *kind) {
    TxLog *e = calloc(1, sizeof *e);
    if (!e) return;
    scpy(e->sender, sizeof e->sender, sender); scpy(e->recipient, sizeof e->recipient, recipient);
    e->amount = amount; e->fee = fee; e->nonce = nonce; e->block = block; scpy(e->kind, sizeof e->kind, kind);
    if (a->tail) a->tail->next = e; else a->head = e;
    a->tail = e;
}

void ledger_free(void) {
    for (int i = 0; i < n_accounts; i++) {
        TxLog *e = accounts[i].head;
        while (e) { TxLog *n = e->next; free(e); e = n; }
    }
    n_accounts = 0; n_utxos = 0;
}

/* ---- UTXO primitives ---- */
static int utxo_add(const char *txid, const char *owner, int amount) {
    if (n_utxos >= MAX_UTXOS || amount <= 0) return -1;
    int idx = 0;
    for (int i = 0; i < n_utxos; i++) if (!strcmp(utxos[i].txid, txid)) idx++;
    Utxo *u = &utxos[n_utxos++];
    scpy(u->txid, sizeof u->txid, txid); u->index = idx; scpy(u->owner, sizeof u->owner, owner);
    u->amount = amount; u->spent = 0;
    return 0;
}

static int utxo_balance(const char *id) {
    int s = 0;
    for (int i = 0; i < n_utxos; i++) if (!utxos[i].spent && !strcmp(utxos[i].owner, id)) s += utxos[i].amount;
    return s;
}

int ledger_balance(const char *id) {
    if (cfg.model == MODEL_UTXO) return utxo_balance(id);
    Account *a = acct_get(id, 0);
    return a ? a->balance : 0;
}

unsigned long ledger_nonce(const char *id) { Account *a = acct_get(id, 0); return a ? a->nonce : 0; }

/* Issue new coins (rewards / mining payouts) to an account. */
int ledger_credit(const char *id, int amount, const char *txid, int block, const char *kind) {
    if (amount <= 0) return 0;
    Account *a = acct_get(id, 1);
    if (!a) return -1;
    a->balance += amount;
    utxo_add(txid, id, amount);
    log_add(a, "SYSTEM", id, amount, 0, 0, block, kind);
    return 0;
}

/*
 * Confirmed token transfer. Validation first (both models), then apply to
 * both. Returns 0 ok, -1 insufficient funds, -2 bad nonce.
 *   UTXO: inputs are consumed, outputs = [recipient amount][change][fee->collector]
 *   Account: sender -= amount+fee, recipient += amount, collector += fee, nonce++
 */
int ledger_transfer(const char *from, const char *to, int amount, int fee, unsigned long nonce,
                    const char *txid, const char *collector, int block, const char *kind) {
    Account *fa = acct_get(from, 1), *ta = acct_get(to, 1), *ca = acct_get(collector, 1);
    if (!fa || !ta || !ca || amount < 0 || fee < 0) return -1;
    int total = amount + fee;
    if (fa->nonce != nonce) return -2;
    if (fa->balance < total || utxo_balance(from) < total) return -1;

    /* --- UTXO apply: select inputs until covered --- */
    int gathered = 0;
    for (int i = 0; i < n_utxos && gathered < total; i++)
        if (!utxos[i].spent && !strcmp(utxos[i].owner, from)) { utxos[i].spent = 1; gathered += utxos[i].amount; }
    if (amount > 0) utxo_add(txid, to, amount);
    if (gathered > total) utxo_add(txid, from, gathered - total);      /* change output */
    if (fee > 0) utxo_add(txid, collector, fee);

    /* --- Account apply --- */
    fa->balance -= total; ta->balance += amount; ca->balance += fee; fa->nonce++;
    log_add(fa, from, to, amount, fee, nonce, block, kind);
    if (ta != fa) log_add(ta, from, to, amount, fee, nonce, block, kind);
    return 0;
}

/* ---- Views ---- */
void ledger_print_utxos(void) {
    int total = 0, cnt = 0;
    printf("UTXO set (unspent outputs):\n  %-18s %-4s %-14s %s\n", "TXID", "IDX", "OWNER", "AMOUNT");
    for (int i = 0; i < n_utxos; i++)
        if (!utxos[i].spent) {
            printf("  %.16s.. %-4d %-14s %d\n", utxos[i].txid, utxos[i].index, utxos[i].owner, utxos[i].amount);
            total += utxos[i].amount; cnt++;
        }
    printf("  -> %d unspent output(s), total value %d\n", cnt, total);
}

void ledger_print_accounts(void) {
    printf("Account balances:\n  %-14s %-8s %s\n", "ACCOUNT", "BALANCE", "NONCE");
    for (int i = 0; i < n_accounts; i++)
        if (accounts[i].balance > 0 || accounts[i].nonce > 0)
            printf("  %-14s %-8d %lu\n", accounts[i].id, accounts[i].balance, accounts[i].nonce);
}

static int known_account(const char *id) { return find_member(id) >= 0 || acct_get(id, 0) != NULL; }

void cmd_token_balance(const char *id) {
    if (!known_account(id)) { printf("ERROR: unknown account %s\n", id); return; }
    printf("%s balance: %d coins  [model: %s]\n", id, ledger_balance(id), cfg.model == MODEL_UTXO ? "UTXO" : "ACCOUNT");
}

void cmd_account_balance(const char *id) {
    if (!known_account(id)) { printf("ERROR: unknown account %s\n", id); return; }
    Account *a = acct_get(id, 0);
    printf("Account %s: balance=%d nonce=%lu\n", id, a ? a->balance : 0, a ? a->nonce : 0);
}

void cmd_transaction_history(const char *id) {
    Account *a = acct_get(id, 0);
    if (!a || find_member(id) < 0) { printf("ERROR: unknown member %s\n", id); return; }
    printf("Transaction history for %s (linked list, oldest first):\n", id);
    printf("  %-4s %-9s %-14s %-14s %-7s %-4s %-6s %s\n", "#", "KIND", "SENDER", "RECIPIENT", "AMOUNT", "FEE", "NONCE", "BLOCK");
    int n = 0;
    for (TxLog *e = a->head; e; e = e->next)
        printf("  %-4d %-9s %-14s %-14s %-7d %-4d %-6lu %d\n", ++n, e->kind, e->sender, e->recipient, e->amount, e->fee, e->nonce, e->block);
    if (!n) printf("  (no transactions)\n");
}

/* Try to consume one specific output by reference. Fails if already spent. */
static int utxo_spend_ref(const char *txid, int idx) {
    for (int i = 0; i < n_utxos; i++)
        if (!strcmp(utxos[i].txid, txid) && utxos[i].index == idx) {
            if (utxos[i].spent) return -1;          /* double spend */
            utxos[i].spent = 1;
            return 0;
        }
    return -2;                                      /* no such output */
}

/* Demonstrates double-spend prevention by really attempting a re-spend. */
void cmd_utxo_selftest(void) {
    for (int i = 0; i < n_utxos; i++)
        if (utxos[i].spent) {
            printf("Attempting to spend UTXO %.16s..:%d owned by %s a second time...\n", utxos[i].txid, utxos[i].index, utxos[i].owner);
            if (utxo_spend_ref(utxos[i].txid, utxos[i].index) == -1)
                printf("REJECTED: output already spent (double-spend prevented).\n");
            else printf("UNEXPECTED: double spend was accepted!\n");
            return;
        }
    printf("No spent outputs exist yet; make a token_transfer first, then rerun.\n");
}
