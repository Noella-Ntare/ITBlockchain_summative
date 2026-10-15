/*
 * pool.c - pending pool, request validation, prioritisation, fraud
 * (misuse) heuristics, and the state-transition engine used when a block
 * is assembled for mining.
 *
 * Every lending action and token transfer is created here as a SIGNED
 * request. Nothing changes registry/ledger state until a block containing
 * the request is mined (see mining.c).
 */
#include <stdarg.h>
#include "libchain.h"

PoolItem pool[MAX_POOL]; int n_pool;

static const Opts NO_OPTS = { "", 0, 0, "", 0, 0 };

/* ------------------------------------------------------------------ */
/* Snapshot of mutable registry state (used to roll back a failed mine)  */
/* ------------------------------------------------------------------ */
typedef struct {
    Copy copies[MAX_COPIES]; int n_copies;
    Member members[MAX_MEMBERS]; int n_members;
    ResEntry queue[MAX_QUEUE]; int n_queue;
} Snap;
static Snap *snap;

static void snapshot_take(void) {
    if (!snap) snap = malloc(sizeof *snap);
    if (!snap) return;
    memcpy(snap->copies, copies, sizeof copies); snap->n_copies = n_copies;
    memcpy(snap->members, members, sizeof members); snap->n_members = n_members;
    memcpy(snap->queue, queue, sizeof queue); snap->n_queue = n_queue;
}

void snapshot_restore(void) {
    if (!snap) return;
    memcpy(copies, snap->copies, sizeof copies); n_copies = snap->n_copies;
    memcpy(members, snap->members, sizeof members); n_members = snap->n_members;
    memcpy(queue, snap->queue, sizeof queue); n_queue = snap->n_queue;
}

/* Notes produced while planning a block; printed only if the block is mined. */
static char notes[16][160]; static int n_notes;
static void plan_note(const char *fmt, ...) {
    if (n_notes >= 16) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(notes[n_notes++], sizeof notes[0], fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */
static int rid_in_use(const char *rid) {
    if (chain_has_record_id(rid)) return 1;
    for (int i = 0; i < n_pool; i++) if (!strcmp(pool[i].request_id, rid)) return 1;
    return 0;
}

static void new_rid(char *out, size_t n, char prefix) {
    do {
        unsigned long c = (prefix == 'R') ? ++cfg.rid_counter : ++cfg.tx_counter;
        snprintf(out, n, "%c%04lu", prefix, c);
    } while (rid_in_use(out));
}

static int pending_lend_count(const char *signer) {
    int n = 0;
    for (int i = 0; i < n_pool; i++) if (pool[i].kind == KIND_LENDING && !strcmp(pool[i].rec.signer_id, signer)) n++;
    return n;
}

static int pending_tx_count(const char *from) {
    int n = 0;
    for (int i = 0; i < n_pool; i++) if (pool[i].kind == KIND_TRANSFER && !strcmp(pool[i].tx.from, from)) n++;
    return n;
}

static int pending_outgoing(const char *from) {
    int s = 0;
    for (int i = 0; i < n_pool; i++)
        if (pool[i].kind == KIND_TRANSFER && !strcmp(pool[i].tx.from, from)) s += pool[i].tx.amount + pool[i].tx.fee;
    return s;
}

/* Is there a pending lending request with this action for this copy/book? */
static int pending_action(int action, const char *copy_id, const char *book_id, const char *member_id) {
    for (int i = 0; i < n_pool; i++) {
        if (pool[i].kind != KIND_LENDING || pool[i].rec.action != action) continue;
        if (copy_id && strcmp(pool[i].rec.copy_id, copy_id)) continue;
        if (book_id && strcmp(pool[i].rec.book_id, book_id)) continue;
        if (member_id && strcmp(pool[i].rec.member_id, member_id)) continue;
        return 1;
    }
    return 0;
}

static void remove_at(int i) {
    memmove(&pool[i], &pool[i + 1], (size_t)(n_pool - i - 1) * sizeof(PoolItem));
    n_pool--;
}

static void add_reason(char *why, const char *txt) {
    if (why[0]) strncat(why, "; ", REASON_LEN - strlen(why) - 1);
    strncat(why, txt, REASON_LEN - strlen(why) - 1);
}

static int check_member(const char *mid) {
    if (!valid_prefixed_id(mid, 'M') || find_member(mid) < 0) { printf("ERROR: member id '%s' is invalid or not in the member registry. Request aborted.\n", mid); return -1; }
    return 0;
}
static int check_book(const char *bid) {
    if (!valid_prefixed_id(bid, 'B') || find_book(bid) < 0) { printf("ERROR: book id '%s' is invalid or not in the book registry. Request aborted.\n", bid); return -1; }
    return 0;
}
static int check_copy(const char *cid) {
    if (!valid_prefixed_id(cid, 'C') || find_copy(cid) < 0) { printf("ERROR: copy id '%s' is invalid or not in the copy registry. Request aborted.\n", cid); return -1; }
    return 0;
}

/* Fill the common fields of a lending record. Returns -1 on a nonce error. */
static int mk_record(Record *r, int action, int si, int mi, int bi, const char *copy_id, const Opts *o) {
    memset(r, 0, sizeof *r);
    if (o->rid[0]) scpy(r->record_id, sizeof r->record_id, o->rid);
    else new_rid(r->record_id, sizeof r->record_id, 'R');
    scpy(r->book_id, sizeof r->book_id, books[bi].id); scpy(r->book_title, sizeof r->book_title, books[bi].title);
    scpy(r->copy_id, sizeof r->copy_id, copy_id);
    scpy(r->member_id, sizeof r->member_id, members[mi].id); scpy(r->member_name, sizeof r->member_name, members[mi].name);
    r->action = action; r->timestamp = sim_now(); r->condition = COND_GOOD;
    scpy(r->signer_id, sizeof r->signer_id, members[si].id); scpy(r->signer_pub, sizeof r->signer_pub, members[si].pub);
    unsigned long expect = members[si].lend_nonce + (unsigned long)pending_lend_count(members[si].id);
    if (o->has_nonce && o->nonce != expect) {
        printf("ERROR: replay protection - nonce %lu rejected; expected next nonce for %s is %lu.\n", o->nonce, members[si].id, expect);
        return -1;
    }
    r->nonce = expect;
    return 0;
}

/* Sign, queue and announce a lending request. why != "" => SUSPICIOUS. */
static int submit_lending(Record *r, int priority, const char *why) {
    if (n_pool >= MAX_POOL) { printf("ERROR: pending pool is full\n"); return -1; }
    int si = find_member(r->signer_id);
    if (record_sign(r, members[si].priv)) { printf("ERROR: could not sign request (missing private key in wallet?)\n"); return -1; }
    PoolItem *it = &pool[n_pool++];
    memset(it, 0, sizeof *it);
    it->kind = KIND_LENDING; it->rec = *r; scpy(it->request_id, sizeof it->request_id, r->record_id);
    it->priority = priority; it->req_date = r->timestamp;
    it->status = why[0] ? PS_SUSPICIOUS : PS_PENDING;
    scpy(it->reason, sizeof it->reason, why);
    printf("Request %s: %s book=%s copy=%s member=%s nonce=%lu signed (ECDSA) and added to pending pool [%s]\n",
           r->record_id, ACTION_NAMES[r->action], r->book_id, r->copy_id, r->member_id, r->nonce, PSTATUS_NAMES[it->status]);
    if (why[0]) printf("  !! FLAGGED SUSPICIOUS: %s\n  !! Withheld from mining until approve_suspicious %s / reject_suspicious %s\n", why, r->record_id, r->record_id);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Lending requests                                                     */
/* ------------------------------------------------------------------ */
int pool_add_borrow(const char *mid, const char *bid, const Opts *o) {
    if (!o) o = &NO_OPTS;
    if (check_member(mid) || check_book(bid)) return -1;
    int mi = find_member(mid), bi = find_book(bid), ci = -1;
    for (int i = 0; i < n_copies && ci < 0; i++)                 /* copy on hold for this member? */
        if (!strcmp(copies[i].book_id, bid) && copies[i].state == ST_RESERVED && !strcmp(copies[i].holder, mid)) ci = i;
    for (int i = 0; i < n_copies && ci < 0; i++)
        if (!strcmp(copies[i].book_id, bid) && copies[i].state == ST_AVAILABLE &&
            !pending_action(ACT_BORROWED, copies[i].id, NULL, NULL)) ci = i;
    if (ci < 0 || pending_action(ACT_BORROWED, copies[ci].id, NULL, NULL)) {
        printf("ERROR: no copy of %s is available to borrow. Use reserve_book to join the queue.\n", bid);
        return -1;
    }
    Record r;
    if (mk_record(&r, ACT_BORROWED, mi, mi, bi, copies[ci].id, o)) return -1;
    r.due_date = r.timestamp + cfg.loan_days * DAY;
    r.condition = copies[ci].condition;

    char why[REASON_LEN] = "", tmp[64];
    int held = 0;
    for (int i = 0; i < n_copies; i++) if (!strcmp(copies[i].holder, mid) && copies[i].state == ST_BORROWED) held++;
    for (int i = 0; i < n_pool; i++)
        if (pool[i].kind == KIND_LENDING && pool[i].rec.action == ACT_BORROWED && !strcmp(pool[i].rec.member_id, mid)) held++;
    if (held >= cfg.max_borrows) { snprintf(tmp, sizeof tmp, "excessive concurrent borrows (limit %d)", cfg.max_borrows); add_reason(why, tmp); }
    int recent = chain_recent_return(mid, bid, r.timestamp - DAY);
    for (int i = 0; i < n_pool && !recent; i++)
        if (pool[i].kind == KIND_LENDING && pool[i].rec.action == ACT_RETURNED && !strcmp(pool[i].rec.member_id, mid) &&
            !strcmp(pool[i].rec.book_id, bid) && pool[i].rec.timestamp >= r.timestamp - DAY) recent = 1;
    if (recent) add_reason(why, "rapid re-borrow of same title within 24h of return");
    if (o->rid[0] && rid_in_use(o->rid)) add_reason(why, "duplicate request_id");
    return submit_lending(&r, 1, why);
}

int pool_add_return(const char *mid, const char *cid, const Opts *o) {
    if (!o) o = &NO_OPTS;
    if (check_member(mid) || check_copy(cid)) return -1;
    int mi = find_member(mid), ci = find_copy(cid), bi = find_book(copies[ci].book_id);
    Copy *c = &copies[ci];
    const Record *lb = find_last_borrowed(cid);
    if (!lb) { printf("ERROR: no BORROWED record for copy %s exists on the chain (a borrow must be mined before it can be returned).\n", cid); return -1; }
    if (c->state != ST_BORROWED) { printf("ERROR: copy %s is %s, not BORROWED.\n", cid, STATE_NAMES[c->state]); return -1; }
    if (strcmp(c->holder, mid)) { printf("ERROR: copy %s is held by %s, not %s.\n", cid, c->holder, mid); return -1; }
    if (pending_action(ACT_RETURNED, cid, NULL, NULL)) { printf("ERROR: a return for copy %s is already pending.\n", cid); return -1; }
    int cond = o->has_cond ? o->cond : c->condition;
    if (cond == COND_LOST) { printf("ERROR: use mark_lost <copy> <reason> for lost copies.\n"); return -1; }
    Record r;
    if (mk_record(&r, ACT_RETURNED, mi, mi, bi, cid, o)) return -1;
    r.due_date = c->due_date; r.condition = cond; scpy(r.reason, sizeof r.reason, o->reason);
    int late = r.timestamp > c->due_date;
    long days = late ? (long)((r.timestamp - c->due_date + DAY - 1) / DAY) : 0;
    r.fine_amount = (int)(days * cfg.fine_per_day);
    char why[REASON_LEN] = "";
    if (cond - c->condition > 1 && !o->reason[0]) add_reason(why, "condition downgraded >1 level without librarian reason code");
    if (o->rid[0] && rid_in_use(o->rid)) add_reason(why, "duplicate request_id");
    if (late) printf("Return is LATE by %ld day(s): fine_amount=%d (rate %d/day).\n", days, r.fine_amount, cfg.fine_per_day);
    return submit_lending(&r, late ? 0 : 1, why);
}

int pool_add_reserve(const char *mid, const char *bid, const Opts *o) {
    if (!o) o = &NO_OPTS;
    if (check_member(mid) || check_book(bid)) return -1;
    int mi = find_member(mid), bi = find_book(bid);
    int free_copies = 0;
    for (int i = 0; i < n_copies; i++) {
        if (strcmp(copies[i].book_id, bid)) continue;
        if (copies[i].state == ST_AVAILABLE && !pending_action(ACT_BORROWED, copies[i].id, NULL, NULL)) free_copies++;
        if (copies[i].state == ST_RESERVED && !strcmp(copies[i].holder, mid)) { printf("ERROR: copy %s is already on hold for %s - use borrow_book.\n", copies[i].id, mid); return -1; }
        if (copies[i].state == ST_BORROWED && !strcmp(copies[i].holder, mid)) { printf("ERROR: %s already holds a copy of %s.\n", mid, bid); return -1; }
    }
    if (free_copies > 0) { printf("ERROR: %d copy(ies) of %s are available - borrow instead of reserving.\n", free_copies, bid); return -1; }
    if (queue_pos(bid, mid) || pending_action(ACT_RESERVED, NULL, bid, mid)) { printf("ERROR: %s already has a reservation for %s.\n", mid, bid); return -1; }
    Record r;
    if (mk_record(&r, ACT_RESERVED, mi, mi, bi, "-", o)) return -1;
    char why[REASON_LEN] = "";
    if (o->rid[0] && rid_in_use(o->rid)) add_reason(why, "duplicate request_id");
    return submit_lending(&r, 1, why);
}

int pool_add_renew(const char *mid, const char *cid, const Opts *o) {
    if (!o) o = &NO_OPTS;
    if (check_member(mid) || check_copy(cid)) return -1;
    int mi = find_member(mid), ci = find_copy(cid), bi = find_book(copies[ci].book_id);
    Copy *c = &copies[ci];
    if (c->state != ST_BORROWED || strcmp(c->holder, mid)) { printf("ERROR: copy %s is not currently borrowed by %s.\n", cid, mid); return -1; }
    if (sim_now() > c->due_date) { printf("ERROR: copy %s is overdue; it cannot be renewed (return it and settle the fine).\n", cid); return -1; }
    if (c->renew_count >= cfg.max_renewals) { printf("ERROR: copy %s already renewed the maximum %d time(s).\n", cid, cfg.max_renewals); return -1; }
    if (queue_len(c->book_id) > 0 || pending_action(ACT_RESERVED, NULL, c->book_id, NULL)) { printf("ERROR: other members have reserved %s - renewal refused.\n", c->book_id); return -1; }
    if (pending_action(ACT_RENEWED, cid, NULL, NULL) || pending_action(ACT_RETURNED, cid, NULL, NULL)) { printf("ERROR: a renew/return for %s is already pending.\n", cid); return -1; }
    Record r;
    if (mk_record(&r, ACT_RENEWED, mi, mi, bi, cid, o)) return -1;
    r.due_date = c->due_date + cfg.renew_days * DAY; r.condition = c->condition;
    char why[REASON_LEN] = "";
    if (o->rid[0] && rid_in_use(o->rid)) add_reason(why, "duplicate request_id");
    return submit_lending(&r, 1, why);
}

/* Librarian-signed OVERDUE records for every late BORROWED copy. */
int pool_scan_overdue(int quiet) {
    expire_offers();
    int flagged = 0; time_t now = sim_now();
    for (int i = 0; i < n_copies; i++) {
        Copy *c = &copies[i];
        if (c->state != ST_BORROWED || now <= c->due_date) continue;
        long days = (long)((now - c->due_date + DAY - 1) / DAY);
        int fine = (int)(days * cfg.fine_per_day);
        if (fine <= c->fine_charged || pending_action(ACT_OVERDUE, c->id, NULL, NULL)) continue;
        int mi = find_member(c->holder), bi = find_book(c->book_id);
        if (mi < 0 || bi < 0) continue;
        Record r; Opts o = NO_OPTS;
        if (mk_record(&r, ACT_OVERDUE, 0, mi, bi, c->id, &o)) continue;
        r.due_date = c->due_date; r.fine_amount = fine; r.condition = c->condition;
        if (!quiet) printf("Copy %s (member %s) is %ld day(s) overdue -> fine accrued %d\n", c->id, c->holder, days, fine);
        if (submit_lending(&r, 0, "") == 0) {
            pool[n_pool - 1].priority = 0; flagged++;
        }
    }
    if (flagged || !quiet) printf("[overdue scan] %d new OVERDUE record(s) queued.\n", flagged);
    return flagged;
}

/* ------------------------------------------------------------------ */
/* Token transfers (also used for fine settlement)                       */
/* ------------------------------------------------------------------ */
int pool_add_transfer(const char *from, const char *to, int amount, const char *memo, const Opts *o) {
    if (!o) o = &NO_OPTS;
    if (check_member(from)) return -1;
    if (strcmp(to, LIBRARY_ACCT) && check_member(to)) return -1;
    if (!strcmp(from, to)) { printf("ERROR: sender and recipient must differ.\n"); return -1; }
    if (amount <= 0 || amount > 1000000) { printf("ERROR: token amount must be a positive integer (<= 1000000).\n"); return -1; }
    int fi = find_member(from);
    unsigned long expect = ledger_nonce(from) + (unsigned long)pending_tx_count(from);
    if (o->has_nonce && o->nonce != expect) {
        printf("ERROR: account nonce %lu rejected (expected %lu) - replayed or out-of-order transaction.\n", o->nonce, expect);
        return -1;
    }
    int need = amount + cfg.tx_fee, avail = ledger_balance(from) - pending_outgoing(from);
    if (avail < need) {
        printf("ERROR: insufficient balance - %s has %d spendable coin(s) but needs %d (amount %d + fee %d). Transaction rejected.\n",
               from, avail, need, amount, cfg.tx_fee);
        return -1;
    }
    if (n_pool >= MAX_POOL) { printf("ERROR: pending pool is full\n"); return -1; }
    PoolItem *it = &pool[n_pool]; memset(it, 0, sizeof *it);
    TokenTx *t = &it->tx;
    t->kind = TX_TRANSFER; scpy(t->from, sizeof t->from, from); scpy(t->to, sizeof t->to, to);
    t->amount = amount; t->fee = cfg.tx_fee; t->nonce = expect; t->timestamp = sim_now();
    scpy(t->memo, sizeof t->memo, memo); scpy(t->signer_pub, sizeof t->signer_pub, members[fi].pub);
    if (tx_sign(t, members[fi].priv)) { printf("ERROR: could not sign transfer.\n"); return -1; }
    new_rid(it->request_id, sizeof it->request_id, 'T');
    it->kind = KIND_TRANSFER; it->priority = !strcmp(memo, "FINE") ? 0 : 1; it->req_date = t->timestamp; it->status = PS_PENDING;
    n_pool++;
    printf("Request %s: TRANSFER %s -> %s amount=%d fee=%d nonce=%lu signed and added to pending pool [PENDING]\n",
           it->request_id, from, to, amount, t->fee, t->nonce);
    return 0;
}

int pool_settle_fine(const char *mid) {
    if (check_member(mid)) return -1;
    int mi = find_member(mid);
    if (members[mi].fines_due <= 0) { printf("%s has no outstanding fines.\n", mid); return -1; }
    for (int i = 0; i < n_pool; i++)
        if (pool[i].kind == KIND_TRANSFER && !strcmp(pool[i].tx.from, mid) && !strcmp(pool[i].tx.memo, "FINE")) {
            printf("ERROR: a fine settlement for %s is already pending.\n", mid); return -1;
        }
    return pool_add_transfer(mid, LIBRARY_ACCT, members[mi].fines_due, "FINE", NULL);
}

void cmd_view_fines(const char *mid) {
    if (mid && check_member(mid)) return;
    printf("Outstanding fines (rate %d coin(s)/day):\n", cfg.fine_per_day);
    int any = 0;
    for (int i = 1; i < n_members; i++) {
        if (mid && strcmp(members[i].id, mid)) continue;
        if (members[i].fines_due > 0 || mid) { printf("  %-6s %-22s fines_due=%d  balance=%d\n", members[i].id, members[i].name, members[i].fines_due, ledger_balance(members[i].id)); any = 1; }
    }
    time_t now = sim_now();
    for (int i = 0; i < n_copies; i++) {
        Copy *c = &copies[i];
        if (c->state != ST_BORROWED || now <= c->due_date || (mid && strcmp(c->holder, mid))) continue;
        long days = (long)((now - c->due_date + DAY - 1) / DAY);
        printf("  copy %-5s overdue %ld day(s), accrued fine %d (booked on chain so far: %d) holder=%s\n", c->id, days, (int)(days * cfg.fine_per_day), c->fine_charged, c->holder);
        any = 1;
    }
    if (!any) printf("  (none)\n");
}

/* ------------------------------------------------------------------ */
/* Ordering, viewing, review workflow                                    */
/* ------------------------------------------------------------------ */
/* Priority: overdue-related first, then oldest request/reservation date. */
static int cmp_pool(const void *a, const void *b) {
    int i = *(const int *)a, j = *(const int *)b;
    if (pool[i].priority != pool[j].priority) return pool[i].priority - pool[j].priority;
    if (pool[i].req_date != pool[j].req_date) return pool[i].req_date < pool[j].req_date ? -1 : 1;
    return i - j;
}

static int sorted_order(int *ord) {
    for (int i = 0; i < n_pool; i++) ord[i] = i;
    qsort(ord, (size_t)n_pool, sizeof(int), cmp_pool);
    return n_pool;
}

void pool_view(void) {
    int ord[MAX_POOL]; sorted_order(ord);
    printf("Pending pool: %d request(s), mining order shown (priority 0 = overdue-related first, then oldest date)\n", n_pool);
    if (!n_pool) return;
    printf("  %-3s %-7s %-9s %-6s %-6s %-7s %-4s %-17s %s\n", "#", "REQ_ID", "ACTION", "BOOK", "COPY", "MEMBER", "PRIO", "DATE", "STATUS");
    for (int k = 0; k < n_pool; k++) {
        PoolItem *it = &pool[ord[k]]; char d[24]; fmt_datetime(it->req_date, d);
        if (it->kind == KIND_LENDING)
            printf("  %-3d %-7s %-9s %-6s %-6s %-7s %-4d %-17s %s\n", k + 1, it->request_id, ACTION_NAMES[it->rec.action], it->rec.book_id,
                   it->rec.copy_id, it->rec.member_id, it->priority, d, PSTATUS_NAMES[it->status]);
        else
            printf("  %-3d %-7s %-9s %-6s %-6s %-7s %-4d %-17s %s  (%s->%s amt=%d fee=%d%s%s)\n", k + 1, it->request_id, it->tx.memo[0] ? "FINE_PAY" : "TRANSFER", "-", "-",
                   it->tx.from, it->priority, d, PSTATUS_NAMES[it->status], it->tx.from, it->tx.to, it->tx.amount, it->tx.fee, "", "");
        if (it->status == PS_SUSPICIOUS) printf("       !! %s\n", it->reason);
    }
}

void pool_fraud_review(void) {
    int n = 0;
    printf("Fraud review queue (SUSPICIOUS requests are never mined until approved):\n");
    for (int i = 0; i < n_pool; i++)
        if (pool[i].status == PS_SUSPICIOUS) {
            PoolItem *it = &pool[i];
            printf("  %-7s %-9s book=%s copy=%s member=%s\n          reason: %s\n", it->request_id, ACTION_NAMES[it->rec.action],
                   it->rec.book_id, it->rec.copy_id, it->rec.member_id, it->reason);
            n++;
        }
    if (!n) printf("  (no suspicious requests)\n");
    else printf("Use approve_suspicious <id> or reject_suspicious <id>.\n");
}

static int find_suspicious(const char *rid) {
    for (int i = 0; i < n_pool; i++) if (pool[i].status == PS_SUSPICIOUS && !strcmp(pool[i].request_id, rid)) return i;
    return -1;
}

int pool_approve(const char *rid) {
    int i = find_suspicious(rid);
    if (i < 0) { printf("ERROR: no SUSPICIOUS request with id '%s'.\n", rid); return -1; }
    pool[i].status = PS_PENDING; pool[i].approved = 1;
    printf("Request %s approved by librarian; now PENDING and eligible for mining.\n", rid);
    return 0;
}

int pool_reject(const char *rid) {
    int i = find_suspicious(rid);
    if (i < 0) { printf("ERROR: no SUSPICIOUS request with id '%s'.\n", rid); return -1; }
    remove_at(i);
    pool_renumber_all();
    printf("Request %s rejected and discarded; later nonces for that signer were renumbered and re-signed.\n", rid);
    return 0;
}

/* After removals, close nonce gaps by re-signing affected pending requests. */
void pool_renumber_all(void) {
    for (int m = 0; m < n_members; m++) {
        unsigned long ln = members[m].lend_nonce, tn = ledger_nonce(members[m].id);
        for (int i = 0; i < n_pool; i++) {
            PoolItem *it = &pool[i];
            if (it->kind == KIND_LENDING && !strcmp(it->rec.signer_id, members[m].id)) {
                if (it->rec.nonce != ln && members[m].priv[0]) { it->rec.nonce = ln; record_sign(&it->rec, members[m].priv); }
                ln++;
            } else if (it->kind == KIND_TRANSFER && !strcmp(it->tx.from, members[m].id)) {
                if (it->tx.nonce != tn && members[m].priv[0]) { it->tx.nonce = tn; tx_sign(&it->tx, members[m].priv); }
                tn++;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* State-transition engine: validate a record and apply it to the        */
/* registries. Used only while assembling a block (snapshot protects it). */
/* ------------------------------------------------------------------ */
#define FAIL(...) do { snprintf(err, en, __VA_ARGS__); return -1; } while (0)

int apply_record(const Record *r, char *err, size_t en, int *reward) {
    *reward = 0;
    int si = find_member(r->signer_id);
    if (si < 0 || strcmp(members[si].pub, r->signer_pub)) FAIL("signer unknown or key not registered");
    if (!record_verify(r)) FAIL("invalid or missing ECDSA signature");
    if (r->nonce != members[si].lend_nonce) FAIL("nonce %lu != expected %lu (replay)", r->nonce, members[si].lend_nonce);
    int mi = find_member(r->member_id), bi = find_book(r->book_id);
    if (mi < 0 || bi < 0) FAIL("member or book missing from registry");
    if (r->fine_amount < 0) FAIL("negative fine");
    Copy *c = NULL;
    if (strcmp(r->copy_id, "-")) {
        int ci = find_copy(r->copy_id);
        if (ci < 0 || strcmp(copies[ci].book_id, r->book_id)) FAIL("copy not valid for this book");
        c = &copies[ci];
    }
    switch (r->action) {
    case ACT_BORROWED:
        if (!c) FAIL("borrow needs a copy");
        if (!(c->state == ST_AVAILABLE || (c->state == ST_RESERVED && !strcmp(c->holder, r->member_id)))) FAIL("copy %s is %s", c->id, STATE_NAMES[c->state]);
        c->state = ST_BORROWED; scpy(c->holder, sizeof c->holder, r->member_id);
        c->due_date = r->due_date; c->renew_count = 0; c->fine_charged = 0;
        break;
    case ACT_RETURNED: {
        if (!c || c->state != ST_BORROWED || strcmp(c->holder, r->member_id)) FAIL("copy not borrowed by this member");
        int delta = r->fine_amount - c->fine_charged;
        if (delta > 0) members[mi].fines_due += delta;
        c->fine_charged = 0; c->renew_count = 0; c->condition = r->condition;
        *reward = (r->timestamp > r->due_date) ? 5 : 10;
        char next[ID_LEN];
        if (queue_pop(c->book_id, next)) {                       /* BORROWED -> RESERVED, offered to queue head */
            c->state = ST_RESERVED; scpy(c->holder, sizeof c->holder, next);
            c->due_date = r->timestamp + cfg.offer_days * DAY;
            plan_note("Copy %s returned and automatically OFFERED to %s (first in reservation queue, %d day hold).", c->id, next, cfg.offer_days);
        } else { c->state = ST_AVAILABLE; c->holder[0] = '\0'; c->due_date = 0; }
        break; }
    case ACT_RESERVED:
        if (count_available(r->book_id) > 0) FAIL("a copy became available; borrow instead");
        if (queue_pos(r->book_id, r->member_id)) FAIL("already in queue");
        queue_push(r->book_id, r->member_id, r->timestamp);
        plan_note("%s joined the reservation queue for %s (position %d).", r->member_id, r->book_id, queue_pos(r->book_id, r->member_id));
        break;
    case ACT_RENEWED:
        if (!c || c->state != ST_BORROWED || strcmp(c->holder, r->member_id)) FAIL("copy not borrowed by this member");
        if (c->renew_count >= cfg.max_renewals) FAIL("renewal limit reached");
        c->due_date = r->due_date; c->renew_count++;
        break;
    case ACT_OVERDUE: {
        if (!c || c->state != ST_BORROWED) FAIL("copy not borrowed");
        int delta = r->fine_amount - c->fine_charged;
        if (delta > 0) members[mi].fines_due += delta;
        c->fine_charged = r->fine_amount;
        break; }
    default: FAIL("unknown action");
    }
    members[si].lend_nonce++;
    return 0;
}

/*
 * Assemble the next block from the pool: take the top-N PENDING requests in
 * priority order, validating and applying each against the registries
 * (SUSPICIOUS requests are never selected). A request that depends on an
 * earlier nonce of the same signer is picked on a later pass, so nonces are
 * always in order inside the chain. Returns the number of requests selected.
 */
int pool_build_block(Block *b, BlockPlan *plan) {
    int ord[MAX_POOL], dropped[MAX_POOL], taken[MAX_POOL];
    int blocked[MAX_MEMBERS] = {0}, picked_tx[MAX_MEMBERS] = {0}, spent[MAX_MEMBERS] = {0};
    int batch = cfg.batch_size < 1 ? 1 : (cfg.batch_size > MAX_RECS ? MAX_RECS : cfg.batch_size);
    memset(plan, 0, sizeof *plan); memset(dropped, 0, sizeof dropped); memset(taken, 0, sizeof taken);
    memset(b, 0, sizeof *b);
    n_notes = 0;
    snapshot_take();
    sorted_order(ord);
    int progress = 1;
    while (progress && plan->nsel < batch) {
        progress = 0;
        for (int k = 0; k < n_pool && plan->nsel < batch; k++) {
            int i = ord[k]; PoolItem *it = &pool[i];
            if (taken[i] || dropped[i] || it->status != PS_PENDING) continue;
            char err[160];
            if (it->kind == KIND_LENDING) {
                int si = find_member(it->rec.signer_id);
                if (si < 0 || blocked[si]) continue;
                if (it->rec.nonce > members[si].lend_nonce) continue;      /* predecessor not mined yet */
                int reward = 0;
                if (apply_record(&it->rec, err, sizeof err, &reward) != 0) {
                    printf("  request %s dropped at mining time: %s\n", it->request_id, err);
                    dropped[i] = 1; plan->drop[plan->ndrop++] = i; blocked[si] = 1; continue;
                }
                b->records[b->record_count++] = it->rec;
                if (reward > 0 && b->tx_count < MAX_TXS) {
                    tx_make_reward(&b->txs[b->tx_count++], it->rec.member_id, reward, it->rec.record_id, it->rec.timestamp);
                }
            } else {
                int fi = find_member(it->tx.from);
                if (fi < 0 || blocked[fi]) continue;
                unsigned long expect = ledger_nonce(it->tx.from) + (unsigned long)picked_tx[fi];
                if (it->tx.nonce > expect) continue;
                if (it->tx.nonce < expect || !tx_verify(&it->tx) || strcmp(members[fi].pub, it->tx.signer_pub) ||
                    ledger_balance(it->tx.from) - spent[fi] < it->tx.amount + it->tx.fee) {
                    printf("  transfer %s dropped at mining time (bad nonce/signature or insufficient funds)\n", it->request_id);
                    dropped[i] = 1; plan->drop[plan->ndrop++] = i; blocked[fi] = 1; continue;
                }
                spent[fi] += it->tx.amount + it->tx.fee; picked_tx[fi]++;
                if (!strcmp(it->tx.memo, "FINE")) {
                    members[fi].fines_due -= it->tx.amount;
                    if (members[fi].fines_due < 0) members[fi].fines_due = 0;
                    plan_note("%s settled fines worth %d coin(s).", it->tx.from, it->tx.amount);
                }
                b->txs[b->tx_count++] = it->tx;
            }
            taken[i] = 1; plan->sel[plan->nsel++] = i; progress = 1;
        }
    }
    if (plan->nsel == 0) { snapshot_restore(); return 0; }
    b->index = chain_len;
    b->timestamp = sim_now();
    if (b->timestamp <= chain[chain_len - 1].timestamp) b->timestamp = chain[chain_len - 1].timestamp + 1;
    scpy(b->previous_hash, sizeof b->previous_hash, chain[chain_len - 1].hash);
    merkle_root(b->records, b->record_count, b->merkle_root);
    b->difficulty = cfg.difficulty;
    block_finalize_tx(b);
    return plan->nsel;
}

/* Remove mined (success) and invalid requests from the pool. */
void pool_finish(const BlockPlan *plan, int success) {
    int rm[MAX_POOL]; memset(rm, 0, sizeof rm);
    for (int i = 0; i < plan->ndrop; i++) rm[plan->drop[i]] = 1;
    if (success) {
        for (int i = 0; i < plan->nsel; i++) rm[plan->sel[i]] = 1;
        for (int i = 0; i < n_notes; i++) printf("  * %s\n", notes[i]);
    }
    int w = 0;
    for (int i = 0; i < n_pool; i++) if (!rm[i]) { if (w != i) pool[w] = pool[i]; w++; }
    n_pool = w;
    n_notes = 0;
    pool_renumber_all();
}
