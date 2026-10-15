/*
 * libchain.h - shared types, constants and prototypes for the
 * Blockchain-Based Library Book Lending Tracker (ALU Summative).
 *
 * Modules:
 *   crypto.c   SHA-256 + ECDSA (secp256k1) via OpenSSL libcrypto
 *   registry.c books / copies / members, state machine, reservation queue
 *   chain.c    records, Merkle tree, blocks, validation, history queries
 *   ledger.c   UTXO model + account model (kept in sync), tx history lists
 *   pool.c     pending pool, prioritisation, fraud heuristics, block planning
 *   mining.c   proof-of-work, solo / pool / cloud mining, block commit
 *   persist.c  text (.dat) serialisation of the full system state
 *   main.c     command-line interface
 */
#ifndef LIBCHAIN_H
#define LIBCHAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---------- sizes ---------- */
#define ID_LEN      24
#define TITLE_LEN   96
#define NAME_LEN    64
#define HASH_LEN    65          /* 64 hex chars + NUL                      */
#define PUB_LEN     140         /* compressed secp256k1 pubkey, hex (66)   */
#define PRIV_LEN    512         /* DER private key, hex                    */
#define SIG_LEN     160         /* DER ECDSA signature, hex (<=144)        */
#define MEMO_LEN    16
#define REASON_LEN  96
#define DAY         86400L

#define MAX_BOOKS    256
#define MAX_COPIES   1024
#define MAX_MEMBERS  256
#define MAX_QUEUE    512
#define MAX_POOL     512
#define MAX_RECS     16         /* hard cap of records per block           */
#define MAX_TXS      32         /* hard cap of token txs per block         */
#define MAX_ACCOUNTS 320
#define MAX_UTXOS    16384
#define POOL_MINERS  4

#define LIBRARIAN_ID "LIBRARIAN"
#define LIBRARY_ACCT "LIBRARY"
#define ZERO_HASH "0000000000000000000000000000000000000000000000000000000000000000"

/* ---------- enumerations ---------- */
enum { ACT_BORROWED, ACT_RETURNED, ACT_RESERVED, ACT_RENEWED, ACT_OVERDUE, ACT_COUNT };
enum { COND_NEW, COND_GOOD, COND_WORN, COND_LOST, COND_COUNT };
enum { ST_AVAILABLE, ST_BORROWED, ST_RESERVED, ST_LOST, ST_COUNT };
enum { PS_PENDING, PS_CONFIRMED, PS_SUSPICIOUS };
enum { KIND_LENDING, KIND_TRANSFER };
enum { TX_REWARD, TX_TRANSFER };
enum { MODEL_UTXO, MODEL_ACCOUNT };

extern const char *ACTION_NAMES[];
extern const char *COND_NAMES[];
extern const char *STATE_NAMES[];
extern const char *PSTATUS_NAMES[];

/* ---------- registries ---------- */
typedef struct { char id[ID_LEN]; char title[TITLE_LEN]; char author[NAME_LEN]; } Book;

typedef struct {
    char id[ID_LEN]; char book_id[ID_LEN];
    int condition; int state;
    char holder[ID_LEN];          /* current_holder_id (or reservation offeree) */
    time_t due_date;              /* due date, or offer expiry when RESERVED    */
    int renew_count;
    int fine_charged;             /* fine already booked via OVERDUE records    */
    char lost_reason[32];
} Copy;

typedef struct {
    char id[ID_LEN]; char name[NAME_LEN]; char course[NAME_LEN];
    char pub[PUB_LEN];            /* public key = on-chain identity            */
    char priv[PRIV_LEN];          /* private key (kept in wallet.dat only)     */
    unsigned long lend_nonce;     /* confirmed lending nonce                   */
    int fines_due;
} Member;

typedef struct { char book_id[ID_LEN]; char member_id[ID_LEN]; time_t date; } ResEntry;

/* ---------- blockchain ---------- */
typedef struct {
    char record_id[ID_LEN]; char book_id[ID_LEN]; char copy_id[ID_LEN];
    char book_title[TITLE_LEN];
    char member_id[ID_LEN]; char member_name[NAME_LEN];
    int action; time_t due_date; int fine_amount;
    unsigned long nonce; time_t timestamp;
    int condition; char reason[32];
    char signer_id[ID_LEN]; char signer_pub[PUB_LEN]; char signature[SIG_LEN];
} Record;

typedef struct {
    char tx_id[HASH_LEN]; int kind;
    char from[ID_LEN]; char to[ID_LEN];
    int amount; int fee; unsigned long nonce; time_t timestamp;
    char memo[MEMO_LEN];            /* reward: record_id; transfer: "" or FINE */
    char signer_pub[PUB_LEN]; char signature[SIG_LEN];
} TokenTx;

typedef struct {
    int index; time_t timestamp; int record_count;
    char previous_hash[HASH_LEN]; char merkle_root[HASH_LEN]; char hash[HASH_LEN];
    char sealed_by[ID_LEN]; int token_reward; char transaction_id[HASH_LEN];
    unsigned long nonce; int difficulty;
    int tx_count;
    Record records[MAX_RECS];
    TokenTx txs[MAX_TXS];
} Block;

/* ---------- pending pool ---------- */
typedef struct {
    char request_id[ID_LEN]; int kind;
    Record rec; TokenTx tx;
    int priority;                 /* 0 = overdue-related, 1 = normal */
    time_t req_date;
    int status; int approved;
    char reason[REASON_LEN];      /* why SUSPICIOUS */
} PoolItem;

typedef struct { int sel[MAX_RECS]; int nsel; int drop[MAX_POOL]; int ndrop; } BlockPlan;

/* ---------- ledger ---------- */
typedef struct TxLog {
    char sender[ID_LEN]; char recipient[ID_LEN];
    int amount; int fee; unsigned long nonce; int block; char kind[12];
    struct TxLog *next;
} TxLog;
typedef struct { char id[ID_LEN]; int balance; unsigned long nonce; TxLog *head, *tail; } Account;
typedef struct { char txid[HASH_LEN]; int index; char owner[ID_LEN]; int amount; int spent; } Utxo;

/* ---------- configuration ---------- */
typedef struct {
    int difficulty, block_reward, batch_size;
    int loan_days, renew_days, max_renewals, max_borrows;
    int fine_per_day, tx_fee, pool_fee_pct, cloud_fee, offer_days;
    int model;
    long clock_offset;
    unsigned long rid_counter, tx_counter;
} Config;

/* ---------- globals ---------- */
extern Config cfg;
extern Book books[MAX_BOOKS]; extern int n_books;
extern Copy copies[MAX_COPIES]; extern int n_copies;
extern Member members[MAX_MEMBERS]; extern int n_members;
extern ResEntry queue[MAX_QUEUE]; extern int n_queue;
extern Block *chain; extern int chain_len;
extern PoolItem pool[MAX_POOL]; extern int n_pool;
extern Account accounts[MAX_ACCOUNTS]; extern int n_accounts;
extern Utxo utxos[MAX_UTXOS]; extern int n_utxos;

/* ---------- util / registry.c ---------- */
void scpy(char *dst, size_t n, const char *src);
time_t sim_now(void);
void fmt_date(time_t t, char *buf);
void fmt_datetime(time_t t, char *buf);
int  parse_date(const char *s, time_t *out);
int  valid_prefixed_id(const char *s, char prefix);
int  valid_text(const char *s, size_t maxlen);
int  find_book(const char *id); int find_member(const char *id); int find_copy(const char *id);
int  count_available(const char *book_id);
int  load_registries(void);
int  add_member(const char *id, const char *name, const char *course, int genkeys);
int  add_book(const char *id, const char *title, const char *author);
int  add_copy_rec(const char *id, const char *book_id, int cond);
int  cond_from_name(const char *s);
int  copy_transition_ok(int from, int to);
int  copy_transition(Copy *c, int to);
void queue_push(const char *book_id, const char *member_id, time_t date);
int  queue_pop(const char *book_id, char *member_out);
int  queue_len(const char *book_id);
int  queue_pos(const char *book_id, const char *member_id);
void cmd_view_member(const char *id); void cmd_view_book(const char *id); void cmd_view_copy(const char *id);
void cmd_reservation_status(const char *book_id);
void expire_offers(void);
int  mark_lost(const char *copy_id, const char *reason);

/* ---------- crypto.c ---------- */
void sha256_hex(const void *data, size_t n, char out[HASH_LEN]);
int  crypto_keygen(char *priv, size_t pl, char *pub, size_t bl);
int  crypto_sign(const char *priv_hex, const char *msg, char *sig_hex, size_t sl);
int  crypto_verify(const char *pub_hex, const char *msg, const char *sig_hex);

/* ---------- chain.c ---------- */
void record_canonical(const Record *r, char *buf, size_t n, int with_sig);
int  record_sign(Record *r, const char *priv);
int  record_verify(const Record *r);
void record_leaf(const Record *r, char out[HASH_LEN]);
void merkle_root(const Record *recs, int n, char out[HASH_LEN]);
void block_hash(const Block *b, char out[HASH_LEN]);
int  pow_ok(const char *hash, int difficulty);
void tx_canonical(const TokenTx *t, char *buf, size_t n);
void tx_make_reward(TokenTx *t, const char *to, int amount, const char *memo, time_t ts);
int  tx_sign(TokenTx *t, const char *priv);
int  tx_verify(const TokenTx *t);
void block_finalize_tx(Block *b);
void chain_init_genesis(void);
void chain_append(const Block *b);
int  validate_chain(int verbose);
const Record *find_last_borrowed(const char *copy_id);
int  chain_has_record_id(const char *rid);
int  chain_recent_return(const char *member_id, const char *book_id, time_t since);
void cmd_chain_view(int last_n);
void cmd_history(const char *member_id, const char *book_id);

/* ---------- ledger.c ---------- */
Account *acct_get(const char *id, int create);
int  ledger_balance(const char *id);
unsigned long ledger_nonce(const char *id);
int  ledger_credit(const char *id, int amount, const char *txid, int block, const char *kind);
int  ledger_transfer(const char *from, const char *to, int amount, int fee, unsigned long nonce,
                     const char *txid, const char *collector, int block, const char *kind);
void ledger_print_utxos(void);
void ledger_print_accounts(void);
void cmd_account_balance(const char *id);
void cmd_token_balance(const char *id);
void cmd_transaction_history(const char *id);
void cmd_utxo_selftest(void);
void ledger_free(void);

/* ---------- pool.c ---------- */
typedef struct { char rid[ID_LEN]; int has_cond; int cond; char reason[32];
                 int has_nonce; unsigned long nonce; } Opts;
int  pool_add_borrow(const char *member_id, const char *book_id, const Opts *o);
int  pool_add_return(const char *member_id, const char *copy_id, const Opts *o);
int  pool_add_reserve(const char *member_id, const char *book_id, const Opts *o);
int  pool_add_renew(const char *member_id, const char *copy_id, const Opts *o);
int  pool_add_transfer(const char *from, const char *to, int amount, const char *memo, const Opts *o);
int  pool_scan_overdue(int quiet);
int  pool_settle_fine(const char *member_id);
void pool_view(void);
void pool_fraud_review(void);
int  pool_approve(const char *rid);
int  pool_reject(const char *rid);
void pool_renumber_all(void);
int  pool_build_block(Block *b, BlockPlan *plan);
void pool_finish(const BlockPlan *plan, int success);
void snapshot_restore(void);
void cmd_view_fines(const char *member_id);
int  apply_record(const Record *r, char *err, size_t en, int *reward);

/* ---------- mining.c ---------- */
extern unsigned long last_attempts;
extern double last_seconds;
extern char last_mode[24];
int  mine_solo(void);
int  mine_pool(void);
int  mine_cloud(int rounds);
void cmd_difficulty_status(void);

/* ---------- persist.c ---------- */
int  state_save(void);
int  state_load(void);
int  state_exists(void);
void wallet_save(void);

#endif
