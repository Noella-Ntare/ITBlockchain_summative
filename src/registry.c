/*
 * registry.c - book / copy / member registries, input validation helpers,
 * simulated clock, copy availability state machine and reservation queue.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include "libchain.h"

const char *ACTION_NAMES[]  = { "BORROWED", "RETURNED", "RESERVED", "RENEWED", "OVERDUE" };
const char *COND_NAMES[]    = { "NEW", "GOOD", "WORN", "LOST" };
const char *STATE_NAMES[]   = { "AVAILABLE", "BORROWED", "RESERVED", "LOST" };
const char *PSTATUS_NAMES[] = { "PENDING", "CONFIRMED", "SUSPICIOUS" };

Config cfg;
Book books[MAX_BOOKS];       int n_books;
Copy copies[MAX_COPIES];     int n_copies;
Member members[MAX_MEMBERS]; int n_members;
ResEntry queue[MAX_QUEUE];   int n_queue;

/* Bounded, always-terminated string copy (avoids strncpy pitfalls). */
void scpy(char *dst, size_t n, const char *src) {
    size_t l = strlen(src);
    if (l >= n) l = n - 1;
    memcpy(dst, src, l);
    dst[l] = '\0';
}

/* ------------------------------------------------------------------ */
/* Simulated clock: real time plus an offset so demos can "fast-forward" */
/* ------------------------------------------------------------------ */
time_t sim_now(void) { return time(NULL) + cfg.clock_offset; }

void fmt_date(time_t t, char *buf) {
    struct tm tmv; gmtime_r(&t, &tmv);
    strftime(buf, 16, "%Y-%m-%d", &tmv);
}
void fmt_datetime(time_t t, char *buf) {
    struct tm tmv; gmtime_r(&t, &tmv);
    strftime(buf, 24, "%Y-%m-%d %H:%M", &tmv);
}

/* Parse strict YYYY-MM-DD; returns 0 on success (UTC midnight). */
int parse_date(const char *s, time_t *out) {
    int y, m, d; char extra;
    if (strlen(s) != 10 || s[4] != '-' || s[7] != '-') return -1;
    if (sscanf(s, "%d-%d-%d%c", &y, &m, &d, &extra) != 3) return -1;
    if (y < 1970 || y > 2100 || m < 1 || m > 12 || d < 1 || d > 31) return -1;
    struct tm tmv; memset(&tmv, 0, sizeof tmv);
    tmv.tm_year = y - 1900; tmv.tm_mon = m - 1; tmv.tm_mday = d;
    time_t t = timegm(&tmv);
    struct tm chk; gmtime_r(&t, &chk);
    if (chk.tm_mday != d || chk.tm_mon != m - 1) return -1;   /* e.g. 2026-02-31 */
    *out = t;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Input validation                                                     */
/* ------------------------------------------------------------------ */
/* IDs look like M001, B002, C010: one prefix letter + 1..8 digits. */
int valid_prefixed_id(const char *s, char prefix) {
    size_t l = strlen(s);
    if (l < 2 || l > 9 || s[0] != prefix) return 0;
    for (size_t i = 1; i < l; i++) if (!isdigit((unsigned char)s[i])) return 0;
    return 1;
}

/* Free text: non-empty, bounded, no '|' (our field separator) or control chars. */
int valid_text(const char *s, size_t maxlen) {
    size_t l = strlen(s);
    if (l == 0 || l >= maxlen) return 0;
    for (size_t i = 0; i < l; i++)
        if (s[i] == '|' || (unsigned char)s[i] < 32) return 0;
    return 1;
}

int find_book(const char *id)   { for (int i = 0; i < n_books; i++)   if (!strcmp(books[i].id, id))   return i; return -1; }
int find_member(const char *id) { for (int i = 0; i < n_members; i++) if (!strcmp(members[i].id, id)) return i; return -1; }
int find_copy(const char *id)   { for (int i = 0; i < n_copies; i++)  if (!strcmp(copies[i].id, id))  return i; return -1; }

int cond_from_name(const char *s) {
    for (int i = 0; i < COND_COUNT; i++) if (!strcasecmp(s, COND_NAMES[i])) return i;
    return -1;
}

int count_available(const char *book_id) {
    int n = 0;
    for (int i = 0; i < n_copies; i++)
        if (!strcmp(copies[i].book_id, book_id) && copies[i].state == ST_AVAILABLE) n++;
    return n;
}

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */
int add_member(const char *id, const char *name, const char *course, int genkeys) {
    if (strcmp(id, LIBRARIAN_ID) && !valid_prefixed_id(id, 'M')) { printf("ERROR: invalid member id '%s' (expected M + digits)\n", id); return -1; }
    if (!valid_text(name, NAME_LEN) || !valid_text(course, NAME_LEN)) { printf("ERROR: invalid name/course text\n"); return -1; }
    if (find_member(id) >= 0) { printf("ERROR: member %s already exists\n", id); return -1; }
    if (n_members >= MAX_MEMBERS) { printf("ERROR: member registry full\n"); return -1; }
    Member *m = &members[n_members];
    memset(m, 0, sizeof *m);
    scpy(m->id, sizeof m->id, id); scpy(m->name, sizeof m->name, name); scpy(m->course, sizeof m->course, course);
    if (genkeys && crypto_keygen(m->priv, sizeof m->priv, m->pub, sizeof m->pub) != 0) {
        printf("ERROR: key generation failed\n"); return -1;
    }
    n_members++;
    acct_get(id, 1);                      /* every member gets a ledger account */
    return n_members - 1;
}

int add_book(const char *id, const char *title, const char *author) {
    if (!valid_prefixed_id(id, 'B')) { printf("ERROR: invalid book id '%s' (expected B + digits)\n", id); return -1; }
    if (!valid_text(title, TITLE_LEN) || !valid_text(author, NAME_LEN)) { printf("ERROR: invalid title/author text\n"); return -1; }
    if (find_book(id) >= 0) { printf("ERROR: book %s already exists\n", id); return -1; }
    if (n_books >= MAX_BOOKS) { printf("ERROR: book registry full\n"); return -1; }
    Book *b = &books[n_books++];
    scpy(b->id, sizeof b->id, id); scpy(b->title, sizeof b->title, title); scpy(b->author, sizeof b->author, author);
    return 0;
}

int add_copy_rec(const char *id, const char *book_id, int cond) {
    if (!valid_prefixed_id(id, 'C')) { printf("ERROR: invalid copy id '%s' (expected C + digits)\n", id); return -1; }
    if (!valid_prefixed_id(book_id, 'B') || find_book(book_id) < 0) { printf("ERROR: book %s not in registry\n", book_id); return -1; }
    if (cond < 0 || cond == COND_LOST) { printf("ERROR: invalid copy condition\n"); return -1; }
    if (find_copy(id) >= 0) { printf("ERROR: copy %s already exists\n", id); return -1; }
    if (n_copies >= MAX_COPIES) { printf("ERROR: copy registry full\n"); return -1; }
    Copy *c = &copies[n_copies++];
    memset(c, 0, sizeof *c);
    scpy(c->id, sizeof c->id, id); scpy(c->book_id, sizeof c->book_id, book_id);
    c->condition = cond; c->state = ST_AVAILABLE;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Loading books.txt, copies.txt, members.txt                           */
/* ------------------------------------------------------------------ */
static int split_csv(char *line, char *f[], int max) {
    int n = 0; char *p = line;
    while (n < max) {
        while (*p == ' ' || *p == '\t') p++;
        f[n++] = p;
        char *c = strchr(p, ',');
        if (!c) break;
        *c = '\0'; p = c + 1;
    }
    for (int i = 0; i < n; i++) {                     /* right-trim */
        size_t l = strlen(f[i]);
        while (l > 0 && isspace((unsigned char)f[i][l - 1])) f[i][--l] = '\0';
    }
    return n;
}

/* Read a CSV-ish file; kind: 'B' books, 'C' copies, 'M' members. */
static int load_one(const char *path, char kind) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("ERROR: required file '%s' not found\n", path); return -1; }
    char line[512]; int good = 0, lineno = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        char *p = line; while (*p == ' ') p++;
        if (!*p || *p == '#') continue;
        char *fl[4]; int n = split_csv(p, fl, 4);
        int rc = -1;
        if (kind == 'B' && n == 3) rc = add_book(fl[0], fl[1], fl[2]);
        else if (kind == 'M' && n == 3) rc = add_member(fl[0], fl[1], fl[2], 1);
        else if (kind == 'C' && n >= 2) {
            int cond = n >= 3 ? cond_from_name(fl[2]) : COND_GOOD;
            rc = add_copy_rec(fl[0], fl[1], cond);
        } else printf("ERROR: %s line %d: wrong number of fields\n", path, lineno);
        if (rc >= 0) good++; else printf("       (skipped %s line %d)\n", path, lineno);
    }
    fclose(f);
    if (good == 0) { printf("ERROR: file '%s' is empty or has no valid entries\n", path); return -1; }
    return 0;
}

int load_registries(void) {
    int bad = 0;
    add_member(LIBRARIAN_ID, "Library Staff", "STAFF", 1);     /* the librarian node signs OVERDUE records */
    if (load_one("books.txt", 'B')) bad++;
    if (load_one("copies.txt", 'C')) bad++;
    if (load_one("members.txt", 'M')) bad++;
    return bad ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* Reservation queue (FIFO per book)                                    */
/* ------------------------------------------------------------------ */
void queue_push(const char *book_id, const char *member_id, time_t date) {
    if (n_queue >= MAX_QUEUE) return;
    scpy(queue[n_queue].book_id, ID_LEN, book_id);
    scpy(queue[n_queue].member_id, ID_LEN, member_id);
    queue[n_queue].date = date;
    n_queue++;
}

/* Remove and return the oldest entry for a title; 1 if one existed. */
int queue_pop(const char *book_id, char *member_out) {
    for (int i = 0; i < n_queue; i++)
        if (!strcmp(queue[i].book_id, book_id)) {
            scpy(member_out, ID_LEN, queue[i].member_id);
            memmove(&queue[i], &queue[i + 1], (size_t)(n_queue - i - 1) * sizeof(ResEntry));
            n_queue--;
            return 1;
        }
    return 0;
}

int queue_len(const char *book_id) {
    int n = 0;
    for (int i = 0; i < n_queue; i++) if (!strcmp(queue[i].book_id, book_id)) n++;
    return n;
}

/* 1-based position of member in the title's queue, 0 if absent. */
int queue_pos(const char *book_id, const char *member_id) {
    int pos = 0;
    for (int i = 0; i < n_queue; i++)
        if (!strcmp(queue[i].book_id, book_id)) {
            pos++;
            if (!strcmp(queue[i].member_id, member_id)) return pos;
        }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Copy availability state machine                                      */
/* ------------------------------------------------------------------ */
/*  AVAILABLE -> BORROWED            (borrow)
 *  BORROWED  -> AVAILABLE|RESERVED  (return; RESERVED if a queue exists)
 *  AVAILABLE|BORROWED -> LOST       (librarian override with reason code)
 *  RESERVED  -> BORROWED            (offered member borrows)
 *  RESERVED  -> AVAILABLE           (offer expired, nobody next in queue)
 */
int copy_transition_ok(int from, int to) {
    switch (from) {
    case ST_AVAILABLE: return to == ST_BORROWED || to == ST_LOST;
    case ST_BORROWED:  return to == ST_AVAILABLE || to == ST_RESERVED || to == ST_LOST;
    case ST_RESERVED:  return to == ST_BORROWED || to == ST_AVAILABLE;
    default:           return 0;                       /* LOST is terminal */
    }
}

int copy_transition(Copy *c, int to) {
    if (!copy_transition_ok(c->state, to)) {
        printf("ERROR: illegal copy state transition %s -> %s for %s\n",
               STATE_NAMES[c->state], STATE_NAMES[to], c->id);
        return -1;
    }
    c->state = to;
    return 0;
}

int mark_lost(const char *copy_id, const char *reason) {
    int ci = find_copy(copy_id);
    if (ci < 0) { printf("ERROR: copy %s not found\n", copy_id); return -1; }
    if (!valid_text(reason, 32) || strchr(reason, ' ')) { printf("ERROR: a reason code (no spaces, max 31 chars) is required\n"); return -1; }
    if (copy_transition(&copies[ci], ST_LOST)) return -1;
    copies[ci].condition = COND_LOST;
    scpy(copies[ci].lost_reason, sizeof copies[ci].lost_reason, reason);
    printf("Copy %s marked LOST (reason code %s) by librarian override.\n", copy_id, reason);
    return 0;
}

/* Offers that nobody claimed in time pass to the next in queue (or free up). */
void expire_offers(void) {
    time_t now = sim_now();
    for (int i = 0; i < n_copies; i++) {
        Copy *c = &copies[i];
        if (c->state != ST_RESERVED || now <= c->due_date) continue;
        printf("Offer of copy %s to %s expired.\n", c->id, c->holder);
        char next[ID_LEN];
        if (queue_pop(c->book_id, next)) {
            scpy(c->holder, sizeof c->holder, next);
            c->due_date = now + cfg.offer_days * DAY;
            printf("  -> now offered to %s\n", next);
        } else {
            copy_transition(c, ST_AVAILABLE);
            c->holder[0] = '\0'; c->due_date = 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Views                                                                */
/* ------------------------------------------------------------------ */
void cmd_view_member(const char *id) {
    for (int i = 0; i < n_members; i++) {
        if (id && strcmp(members[i].id, id)) continue;
        if (!id && i == 0) continue;                      /* hide librarian in list-all */
        Member *m = &members[i]; int held = 0;
        for (int c = 0; c < n_copies; c++)
            if (!strcmp(copies[c].holder, m->id) && copies[c].state == ST_BORROWED) held++;
        printf("%-10s %-24s %-8s held=%d fines_due=%d lend_nonce=%lu\n", m->id, m->name, m->course, held, m->fines_due, m->lend_nonce);
        printf("           public key: %.24s...\n", m->pub);
        if (id) return;
    }
    if (id) printf("ERROR: member %s not found\n", id);
}

void cmd_view_book(const char *id) {
    for (int i = 0; i < n_books; i++) {
        if (id && strcmp(books[i].id, id)) continue;
        int total = 0;
        for (int c = 0; c < n_copies; c++) if (!strcmp(copies[c].book_id, books[i].id)) total++;
        printf("%-6s %-34s %-22s copies=%d available=%d queue=%d\n", books[i].id, books[i].title, books[i].author,
               total, count_available(books[i].id), queue_len(books[i].id));
        if (id) return;
    }
    if (id) printf("ERROR: book %s not found\n", id);
}

void cmd_view_copy(const char *id) {
    int found = 0;
    for (int i = 0; i < n_copies; i++) {
        if (id && strcmp(copies[i].id, id)) continue;
        Copy *c = &copies[i]; char d[24] = "-";
        if (c->due_date) fmt_date(c->due_date, d);
        printf("%-6s book=%-5s cond=%-5s state=%-9s holder=%-6s due=%s renewals=%d%s%s\n", c->id, c->book_id,
               COND_NAMES[c->condition], STATE_NAMES[c->state], c->holder[0] ? c->holder : "-", d, c->renew_count,
               c->lost_reason[0] ? " lost_reason=" : "", c->lost_reason);
        found = 1;
        if (id) return;
    }
    if (id && !found) printf("ERROR: copy %s not found\n", id);
}

void cmd_reservation_status(const char *book_id) {
    if (find_book(book_id) < 0) { printf("ERROR: book %s not found\n", book_id); return; }
    printf("Reservation queue for %s (%s): %d waiting\n", book_id, books[find_book(book_id)].title, queue_len(book_id));
    int pos = 0;
    for (int i = 0; i < n_queue; i++)
        if (!strcmp(queue[i].book_id, book_id)) {
            char d[24]; fmt_datetime(queue[i].date, d);
            printf("  #%d %-6s reserved on %s\n", ++pos, queue[i].member_id, d);
        }
    for (int i = 0; i < n_copies; i++)
        if (!strcmp(copies[i].book_id, book_id) && copies[i].state == ST_RESERVED) {
            char d[24]; fmt_datetime(copies[i].due_date, d);
            printf("  Copy %s is on hold for %s until %s\n", copies[i].id, copies[i].holder, d);
        }
}
