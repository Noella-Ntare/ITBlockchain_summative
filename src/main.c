/*
 * main.c - command-line interface and program start-up.
 *
 * Usage:
 *   ./libchain                       interactive shell (also reads piped scripts)
 *   ./libchain <command> [args...]   run a single command (state persists on disk)
 *   Options (before the command): --difficulty N (1-4)  --model utxo|account  --dir DIR
 */
#include <unistd.h>
#include "libchain.h"

extern void config_defaults(void);

static int session_locked;      /* loaded chain must pass validate_chain first */
static int overdue_scanned;

void config_defaults(void) {
    memset(&cfg, 0, sizeof cfg);
    cfg.difficulty = 2; cfg.block_reward = 100; cfg.batch_size = 4;
    cfg.loan_days = 14; cfg.renew_days = 7; cfg.max_renewals = 2; cfg.max_borrows = 3;
    cfg.fine_per_day = 1; cfg.tx_fee = 1; cfg.pool_fee_pct = 2; cfg.cloud_fee = 60; cfg.offer_days = 3;
    cfg.model = MODEL_UTXO;
}

/* ---- tokenizer: whitespace separated, "double quotes" group words ---- */
static int tokenize(char *line, char *argv[], int max) {
    int n = 0; char *p = line;
    while (*p && n < max) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (*p == '"') { argv[n++] = ++p; while (*p && *p != '"') p++; if (*p) *p++ = '\0'; }
        else { argv[n++] = p; while (*p && *p != ' ' && *p != '\t') p++; if (*p) *p++ = '\0'; }
    }
    return n;
}

/* key=value options after the positional arguments: rid= cond= reason= nonce= */
static int parse_opts(int argc, char **argv, int start, Opts *o) {
    memset(o, 0, sizeof *o);
    for (int i = start; i < argc; i++) {
        if (!strncmp(argv[i], "rid=", 4)) {
            if (!valid_text(argv[i] + 4, ID_LEN) || strchr(argv[i] + 4, ' ')) { printf("ERROR: invalid rid\n"); return -1; }
            scpy(o->rid, sizeof o->rid, argv[i] + 4);
        } else if (!strncmp(argv[i], "cond=", 5)) {
            o->cond = cond_from_name(argv[i] + 5); o->has_cond = 1;
            if (o->cond < 0) { printf("ERROR: condition must be NEW, GOOD, WORN or LOST\n"); return -1; }
        } else if (!strncmp(argv[i], "reason=", 7)) {
            if (!valid_text(argv[i] + 7, sizeof o->reason)) { printf("ERROR: invalid reason code\n"); return -1; }
            scpy(o->reason, sizeof o->reason, argv[i] + 7);
        } else if (!strncmp(argv[i], "nonce=", 6)) {
            char *end; long v = strtol(argv[i] + 6, &end, 10);
            if (*end || v < 0) { printf("ERROR: nonce must be a non-negative integer\n"); return -1; }
            o->nonce = (unsigned long)v; o->has_nonce = 1;
        } else { printf("ERROR: unknown option '%s'\n", argv[i]); return -1; }
    }
    return 0;
}

static int parse_amount(const char *s, int *out) {
    char *end; long v = strtol(s, &end, 10);
    if (*s == '\0' || *end || v <= 0 || v > 1000000) { printf("ERROR: amount must be a positive whole number (max 1000000).\n"); return -1; }
    *out = (int)v; return 0;
}

static void help(void) {
    printf(
"Membership : register_member <id> \"<name>\" <course> | view_member [id] | member_nonce <id>\n"
"Books/Copy : register_book <id> \"<title>\" \"<author>\" | view_book [id] | add_copy <copy> <book> [cond] | view_copy [id] | mark_lost <copy> <reason>\n"
"Lending    : borrow_book <member> <book> | return_book <member> <copy> [cond=X reason=CODE] | renew_book <member> <copy>\n"
"             reserve_book <member> <book> | reservation_status <book>      (options: rid=ID nonce=N)\n"
"Fines      : check_overdue | view_fines [member] | settle_fine <member>\n"
"Tokens     : token_transfer <from> <to> <amt> | token_balance <id> | utxo_view | account_balance <id>\n"
"             account_transfer <from> <to> <amt> [nonce=N] | account_nonce <id> | transaction_history <id> | utxo_selftest\n"
"Chain/mine : pool_view | mine_solo | mine_pool | mine_cloud <rounds 1-5> | chain_view [n] | validate_chain\n"
"             chain_save | chain_load | difficulty_status | set_difficulty <1-4> | set_model <utxo|account>\n"
"Fraud/audit: fraud_review | approve_suspicious <id> | reject_suspicious <id> | lending_history | member_history <id> | book_history <id>\n"
"Utilities  : config [key value] | show_date | advance_time <days> | set_date <YYYY-MM-DD> | simulate_tamper <block> | help | quit\n");
}

static void cmd_config(int argc, char **argv) {
    struct { const char *k; int *v; int lo, hi; } t[] = {
        {"block_reward", &cfg.block_reward, 1, 100000}, {"batch_size", &cfg.batch_size, 1, MAX_RECS}, {"loan_days", &cfg.loan_days, 1, 365},
        {"renew_days", &cfg.renew_days, 1, 365}, {"max_renewals", &cfg.max_renewals, 0, 10}, {"max_borrows", &cfg.max_borrows, 1, 50},
        {"fine_per_day", &cfg.fine_per_day, 0, 1000}, {"tx_fee", &cfg.tx_fee, 0, 100}, {"pool_fee_pct", &cfg.pool_fee_pct, 0, 50},
        {"cloud_fee", &cfg.cloud_fee, 0, 100000}, {"offer_days", &cfg.offer_days, 1, 30} };
    int nt = (int)(sizeof t / sizeof t[0]);
    if (argc == 1) { for (int i = 0; i < nt; i++) printf("  %-14s = %d\n", t[i].k, *t[i].v); return; }
    if (argc != 3) { printf("usage: config [key value]\n"); return; }
    char *end; long v = strtol(argv[2], &end, 10);
    for (int i = 0; i < nt; i++)
        if (!strcmp(argv[1], t[i].k)) {
            if (*end || v < t[i].lo || v > t[i].hi) { printf("ERROR: %s must be an integer in %d..%d\n", t[i].k, t[i].lo, t[i].hi); return; }
            *t[i].v = (int)v; printf("%s set to %ld\n", t[i].k, v); return;
        }
    printf("ERROR: unknown config key '%s'\n", argv[1]);
}

static void set_difficulty(const char *s) {
    char *end; long v = strtol(s, &end, 10);
    if (*end || v < 1 || v > 4) { printf("ERROR: difficulty must be 1..4\n"); return; }
    cfg.difficulty = (int)v; printf("Difficulty set to %ld\n", v);
}

static void tamper(const char *s) {
    char *end; long v = strtol(s, &end, 10);
    if (*end || v < 1 || v >= chain_len) { printf("ERROR: choose an existing non-genesis block index (1..%d)\n", chain_len - 1); return; }
    Block *b = &chain[v];
    if (b->record_count > 0) { b->records[0].fine_amount += 100; printf("TAMPER: block %ld record %s fine_amount changed in memory (not saved).\n", v, b->records[0].record_id); }
    else { b->token_reward += 50; printf("TAMPER: block %ld token_reward changed in memory (not saved).\n", v); }
    session_locked = 1;
}

/* Commands that never change state or need a validated chain. */
static int is_open_cmd(const char *c) {
    return !strcmp(c, "validate_chain") || !strcmp(c, "chain_load") || !strcmp(c, "help") || !strcmp(c, "quit") ||
           !strcmp(c, "exit") || !strcmp(c, "difficulty_status") || !strcmp(c, "show_date");
}

/* Returns 1 to quit. */
static int dispatch(int argc, char **argv) {
    const char *c = argv[0]; Opts o;
    if (session_locked && !is_open_cmd(c)) {
        printf("LOCKED: the chain was loaded from disk (or failed a check). Run validate_chain first; no other operations are permitted until it passes.\n");
        return 0;
    }
    if (!session_locked && !overdue_scanned && strcmp(c, "quit") && strcmp(c, "exit") && strcmp(c, "help")) {
        overdue_scanned = 1; pool_scan_overdue(1);          /* automatic overdue scan once per invocation */
    }
#define NEED(n, usage) do { if (argc < (n)) { printf("usage: %s\n", usage); return 0; } } while (0)
    if (!strcmp(c, "quit") || !strcmp(c, "exit")) return 1;
    else if (!strcmp(c, "help")) help();
    else if (!strcmp(c, "register_member")) { NEED(4, "register_member <id> \"<name>\" <course>");
        if (!valid_prefixed_id(argv[1], 'M')) printf("ERROR: member id must look like M006\n");
        else if (add_member(argv[1], argv[2], argv[3], 1) >= 0) printf("Member %s registered; ECDSA key pair generated (public key = on-chain identity).\n", argv[1]); }
    else if (!strcmp(c, "view_member")) cmd_view_member(argc > 1 ? argv[1] : NULL);
    else if (!strcmp(c, "member_nonce")) { NEED(2, "member_nonce <id>");
        int mi = find_member(argv[1]);
        if (mi < 0) printf("ERROR: member %s not found\n", argv[1]);
        else { int pend = 0; for (int i = 0; i < n_pool; i++) if (pool[i].kind == KIND_LENDING && !strcmp(pool[i].rec.signer_id, argv[1])) pend++;
               printf("%s lending nonce: confirmed=%lu, expected next request nonce=%lu (%d pending)\n", argv[1], members[mi].lend_nonce, members[mi].lend_nonce + (unsigned long)pend, pend); } }
    else if (!strcmp(c, "register_book")) { NEED(4, "register_book <id> \"<title>\" \"<author>\"");
        if (add_book(argv[1], argv[2], argv[3]) >= 0) printf("Book %s registered. Use add_copy to add physical copies.\n", argv[1]); }
    else if (!strcmp(c, "view_book")) cmd_view_book(argc > 1 ? argv[1] : NULL);
    else if (!strcmp(c, "add_copy")) { NEED(3, "add_copy <copy_id> <book_id> [NEW|GOOD|WORN]");
        int cond = argc > 3 ? cond_from_name(argv[3]) : COND_GOOD;
        if (add_copy_rec(argv[1], argv[2], cond) >= 0) printf("Copy %s of %s added (AVAILABLE).\n", argv[1], argv[2]); }
    else if (!strcmp(c, "view_copy")) cmd_view_copy(argc > 1 ? argv[1] : NULL);
    else if (!strcmp(c, "mark_lost")) { NEED(3, "mark_lost <copy_id> <reason_code>"); mark_lost(argv[1], argv[2]); }
    else if (!strcmp(c, "borrow_book")) { NEED(3, "borrow_book <member_id> <book_id> [rid=ID] [nonce=N]");
        if (!parse_opts(argc, argv, 3, &o)) pool_add_borrow(argv[1], argv[2], &o); }
    else if (!strcmp(c, "return_book")) { NEED(3, "return_book <member_id> <copy_id> [cond=X] [reason=CODE] [rid=ID]");
        if (!parse_opts(argc, argv, 3, &o)) pool_add_return(argv[1], argv[2], &o); }
    else if (!strcmp(c, "renew_book")) { NEED(3, "renew_book <member_id> <copy_id>");
        if (!parse_opts(argc, argv, 3, &o)) pool_add_renew(argv[1], argv[2], &o); }
    else if (!strcmp(c, "reserve_book")) { NEED(3, "reserve_book <member_id> <book_id>");
        if (!parse_opts(argc, argv, 3, &o)) pool_add_reserve(argv[1], argv[2], &o); }
    else if (!strcmp(c, "reservation_status")) { NEED(2, "reservation_status <book_id>"); cmd_reservation_status(argv[1]); }
    else if (!strcmp(c, "check_overdue")) { expire_offers(); pool_scan_overdue(0); }
    else if (!strcmp(c, "view_fines")) cmd_view_fines(argc > 1 ? argv[1] : NULL);
    else if (!strcmp(c, "settle_fine")) { NEED(2, "settle_fine <member_id>"); pool_settle_fine(argv[1]); }
    else if (!strcmp(c, "token_transfer") || !strcmp(c, "account_transfer")) { NEED(4, "token_transfer <from> <to> <amount> [nonce=N]");
        int amt;
        if (!parse_amount(argv[3], &amt) && !parse_opts(argc, argv, 4, &o)) pool_add_transfer(argv[1], argv[2], amt, "", &o); }
    else if (!strcmp(c, "token_balance")) { NEED(2, "token_balance <id>"); cmd_token_balance(argv[1]); }
    else if (!strcmp(c, "utxo_view")) ledger_print_utxos();
    else if (!strcmp(c, "utxo_selftest")) cmd_utxo_selftest();
    else if (!strcmp(c, "account_balance")) { NEED(2, "account_balance <id>"); cmd_account_balance(argv[1]); }
    else if (!strcmp(c, "account_nonce")) { NEED(2, "account_nonce <id>");
        if (find_member(argv[1]) < 0) printf("ERROR: member %s not found\n", argv[1]);
        else { int pend = 0; for (int i = 0; i < n_pool; i++) if (pool[i].kind == KIND_TRANSFER && !strcmp(pool[i].tx.from, argv[1])) pend++;
               printf("%s account nonce: confirmed=%lu, next outgoing transaction must use nonce %lu\n", argv[1], ledger_nonce(argv[1]), ledger_nonce(argv[1]) + (unsigned long)pend); } }
    else if (!strcmp(c, "transaction_history")) { NEED(2, "transaction_history <member_id>"); cmd_transaction_history(argv[1]); }
    else if (!strcmp(c, "pool_view")) pool_view();
    else if (!strcmp(c, "mine_solo")) mine_solo();
    else if (!strcmp(c, "mine_pool")) mine_pool();
    else if (!strcmp(c, "mine_cloud")) { NEED(2, "mine_cloud <rounds 1-5>");
        char *end; long r = strtol(argv[1], &end, 10);
        if (*end || r < 1 || r > 5) printf("ERROR: rental duration must be 1 to 5 rounds.\n"); else mine_cloud((int)r); }
    else if (!strcmp(c, "chain_view")) cmd_chain_view(argc > 1 ? atoi(argv[1]) : 0);
    else if (!strcmp(c, "validate_chain")) {
        printf("Validating %d block(s)...\n", chain_len);
        if (validate_chain(1)) { session_locked = 0; } else { session_locked = 1; printf("Session stays LOCKED. Use chain_load to restore the last saved chain.\n"); }
    }
    else if (!strcmp(c, "chain_save")) { if (state_save() == 0) printf("State saved to chain.dat (%d block(s), %d pending request(s)).\n", chain_len, n_pool); }
    else if (!strcmp(c, "chain_load")) {
        if (state_load() == 0) { session_locked = 1; overdue_scanned = 0; printf("State loaded from chain.dat. Run validate_chain before any further operation.\n"); }
        else if (chain_len == 0) { printf("Load failed and memory was cleared - restart the program.\n"); }
    }
    else if (!strcmp(c, "difficulty_status")) cmd_difficulty_status();
    else if (!strcmp(c, "set_difficulty")) { NEED(2, "set_difficulty <1-4>"); set_difficulty(argv[1]); }
    else if (!strcmp(c, "set_model")) { NEED(2, "set_model <utxo|account>");
        if (!strcasecmp(argv[1], "utxo")) { cfg.model = MODEL_UTXO; printf("Token model: UTXO\n"); }
        else if (!strcasecmp(argv[1], "account")) { cfg.model = MODEL_ACCOUNT; printf("Token model: ACCOUNT\n"); }
        else printf("ERROR: model must be utxo or account\n"); }
    else if (!strcmp(c, "fraud_review")) pool_fraud_review();
    else if (!strcmp(c, "approve_suspicious")) { NEED(2, "approve_suspicious <request_id>"); pool_approve(argv[1]); }
    else if (!strcmp(c, "reject_suspicious")) { NEED(2, "reject_suspicious <request_id>"); pool_reject(argv[1]); }
    else if (!strcmp(c, "lending_history")) cmd_history(NULL, NULL);
    else if (!strcmp(c, "member_history")) { NEED(2, "member_history <member_id>");
        if (find_member(argv[1]) < 0) printf("ERROR: member %s not found\n", argv[1]); else cmd_history(argv[1], NULL); }
    else if (!strcmp(c, "book_history")) { NEED(2, "book_history <book_id>");
        if (find_book(argv[1]) < 0) printf("ERROR: book %s not found\n", argv[1]); else cmd_history(NULL, argv[1]); }
    else if (!strcmp(c, "config")) cmd_config(argc, argv);
    else if (!strcmp(c, "show_date")) { char d[24]; fmt_datetime(sim_now(), d); printf("Simulated date/time: %s UTC (clock offset %+ld days)\n", d, cfg.clock_offset / DAY); }
    else if (!strcmp(c, "advance_time")) { NEED(2, "advance_time <days>");
        char *end; long d = strtol(argv[1], &end, 10);
        if (*end || d < 1 || d > 3650) printf("ERROR: days must be a whole number 1..3650\n");
        else { cfg.clock_offset += d * DAY; char s[24]; fmt_datetime(sim_now(), s); printf("Clock advanced %ld day(s): now %s UTC\n", d, s); pool_scan_overdue(0); } }
    else if (!strcmp(c, "set_date")) { NEED(2, "set_date <YYYY-MM-DD>");
        time_t t;
        if (parse_date(argv[1], &t)) printf("ERROR: date must be a real calendar date in YYYY-MM-DD format\n");
        else if (t <= sim_now()) printf("ERROR: date is in the past (current simulated time can only move forward)\n");
        else { cfg.clock_offset = (long)(t - time(NULL)); printf("Clock set to %s\n", argv[1]); pool_scan_overdue(0); } }
    else if (!strcmp(c, "simulate_tamper")) { NEED(2, "simulate_tamper <block_index>"); tamper(argv[1]); }
    else printf("Unknown command '%s'. Type help.\n", c);
    return 0;
}

static void startup(void) {
    if (state_exists()) {
        if (state_load() == 0) {
            session_locked = 1;
            printf("Saved chain found: restored %d block(s), %d pending request(s), %d member(s).\n", chain_len, n_pool, n_members - 1);
            printf("Run validate_chain before any further operation.\n");
            return;
        }
        printf("Could not restore saved state; refusing to overwrite it. Fix or remove chain.dat.\n");
        exit(1);
    }
    if (load_registries() != 0) { printf("Cannot start: registry files are missing or empty.\n"); exit(1); }
    chain_init_genesis();
    printf("No saved chain: initialised new chain (genesis hash %.16s...). Loaded %d books, %d copies, %d members.\n",
           chain[0].hash, n_books, n_copies, n_members - 1);
    state_save();
}

int main(int argc, char **argv) {
    int i = 1, model_set = 0, diff = 0, model = MODEL_UTXO;
    config_defaults();
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    for (; i < argc && !strncmp(argv[i], "--", 2); i++) {
        if (!strcmp(argv[i], "--difficulty") && i + 1 < argc) { diff = atoi(argv[++i]); if (diff < 1 || diff > 4) { fprintf(stderr, "difficulty must be 1..4\n"); return 1; } }
        else if (!strcmp(argv[i], "--model") && i + 1 < argc) {
            i++; model_set = 1;
            if (!strcasecmp(argv[i], "account")) model = MODEL_ACCOUNT; else if (!strcasecmp(argv[i], "utxo")) model = MODEL_UTXO;
            else { fprintf(stderr, "model must be utxo or account\n"); return 1; }
        }
        else if (!strcmp(argv[i], "--dir") && i + 1 < argc) { if (chdir(argv[++i])) { perror("chdir"); return 1; } }
        else { fprintf(stderr, "unknown option %s\n", argv[i]); return 1; }
    }
    startup();
    if (diff) cfg.difficulty = diff;           /* command-line args override saved config */
    if (model_set) cfg.model = model;

    if (i < argc) {                            /* single-command mode */
        if (session_locked && strcmp(argv[i], "validate_chain") && strcmp(argv[i], "help")) {
            printf("Loaded chain: validating before running '%s'...\n", argv[i]);
            if (validate_chain(0)) { session_locked = 0; printf("Chain valid (%d block(s)).\n", chain_len); }
            else printf("CHAIN INVALID - run validate_chain for details. Operations refused.\n");
        }
        dispatch(argc - i, argv + i);
    } else {                                   /* interactive / scripted mode */
        char line[1024], *av[32]; int tty = isatty(0);
        if (tty) printf("Type 'help' for commands.\n");
        for (;;) {
            if (tty) { printf("libchain> "); fflush(stdout); }
            if (!fgets(line, sizeof line, stdin)) break;
            line[strcspn(line, "\r\n")] = '\0';
            if (!tty && line[0]) printf("libchain> %s\n", line);
            int n = tokenize(line, av, 32);
            if (n == 0 || av[0][0] == '#') continue;
            if (dispatch(n, av)) break;
            if (!session_locked) state_save();      /* persist after every command */
            fflush(stdout);
        }
    }
    if (!session_locked) { state_save(); }
    else if (i < argc) { /* single command mode with locked session: nothing to save */ }
    ledger_free(); free(chain);
    return 0;
}
