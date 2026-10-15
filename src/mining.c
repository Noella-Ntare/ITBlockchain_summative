/*
 * mining.c - proof-of-work and the three mining simulations.
 *
 * All three modes confirm the SAME kind of block, planned from the same
 * pending pool by pool_build_block(). They differ in who searches for the
 * nonce and how the block reward is distributed.
 */
#include "libchain.h"

unsigned long last_attempts; double last_seconds; char last_mode[24] = "-";

static unsigned long pow16(int d) { unsigned long p = 1; while (d-- > 0) p *= 16; return p; }

/* Print the ledger view after a block is confirmed. */
static void print_after_block(void) {
    if (cfg.model == MODEL_UTXO) ledger_print_utxos();
    else ledger_print_accounts();
}

/* Plan a block; on empty pool explain why. Returns number of requests selected. */
static int prepare(Block *b, BlockPlan *plan) {
    int n = pool_build_block(b, plan);
    if (n == 0) {
        pool_finish(plan, 0);
        int susp = 0, pend = 0;
        for (int i = 0; i < n_pool; i++) { if (pool[i].status == PS_SUSPICIOUS) susp++; else pend++; }
        printf("Nothing to mine: no mineable requests available");
        if (susp) printf(" (%d SUSPICIOUS request(s) are withheld - see fraud_review)", susp);
        if (pend) printf(" (%d PENDING request(s) are waiting behind an earlier suspicious request from the same signer: nonces must be mined in order)", pend);
        printf(".\n");
    } else {
        printf("Block %d planned: %d request(s) (%d record(s), %d token tx(s)), difficulty %d (hash must start with ", b->index, n, b->record_count, b->tx_count, b->difficulty);
        for (int i = 0; i < b->difficulty; i++) putchar('0');
        printf(")\n");
    }
    return n;
}

/* Append the mined block and apply its token transactions to both ledgers. */
static void commit(Block *b, const BlockPlan *plan, const char *collector) {
    chain_append(b);
    for (int i = 0; i < b->tx_count; i++) {
        const TokenTx *t = &b->txs[i];
        if (t->kind == TX_REWARD) ledger_credit(t->to, t->amount, t->tx_id, b->index, "REWARD");
        else if (ledger_transfer(t->from, t->to, t->amount, t->fee, t->nonce, t->tx_id, collector, b->index,
                                 t->memo[0] ? "FINE" : "TRANSFER") != 0)
            printf("  internal warning: transfer %.10s could not be applied to the ledger\n", t->tx_id);
    }
    pool_finish(plan, 1);
}

static void credit_miner(const char *id, int amt, int blk, const char *kind) {
    char seed[96], txid[HASH_LEN];
    snprintf(seed, sizeof seed, "MINING|%d|%s|%lu", blk, id, (unsigned long)time(NULL));
    sha256_hex(seed, strlen(seed), txid);
    ledger_credit(id, amt, txid, blk, kind);
}

static void summary(const Block *b, unsigned long attempts, double secs) {
    last_attempts = attempts; last_seconds = secs;
    printf("CONFIRMED block %d  hash=%s\n", b->index, b->hash);
    printf("  difficulty=%d  nonce=%lu  hash attempts=%lu  time=%.3fs  member token rewards in block=%d\n",
           b->difficulty, b->nonce, attempts, secs, b->token_reward);
}

/* ---------------------------- SOLO ---------------------------------- */
int mine_solo(void) {
    Block b; BlockPlan plan;
    if (prepare(&b, &plan) == 0) return -1;
    scpy(b.sealed_by, sizeof b.sealed_by, "MINER-SOLO");
    unsigned long attempts = 0; clock_t t0 = clock();
    for (b.nonce = 0;; b.nonce++) {
        block_hash(&b, b.hash); attempts++;
        if (pow_ok(b.hash, b.difficulty)) break;
    }
    double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;
    scpy(last_mode, sizeof last_mode, "solo");
    commit(&b, &plan, "MINER-SOLO");
    summary(&b, attempts, secs);
    credit_miner("MINER-SOLO", cfg.block_reward, b.index, "MINING");
    printf("  SOLO mining reward: %d coins -> MINER-SOLO (full reward, on top of member rewards)\n", cfg.block_reward);
    print_after_block();
    return 0;
}

/* ---------------------------- POOL ---------------------------------- */
int mine_pool(void) {
    Block b; BlockPlan plan;
    if (prepare(&b, &plan) == 0) return -1;
    scpy(b.sealed_by, sizeof b.sealed_by, "MINING-POOL");
    unsigned long rate[POOL_MINERS], att[POOL_MINERS] = {0}, total = 0, nonce = 0;
    int found = 0, winner = -1;
    for (int i = 0; i < POOL_MINERS; i++) rate[i] = 50 + (unsigned long)(rand() % 251);   /* attempts per round */
    clock_t t0 = clock(); unsigned long rounds = 0;
    while (!found) {
        rounds++;
        for (int m = 0; m < POOL_MINERS && !found; m++)
            for (unsigned long a = 0; a < rate[m]; a++) {
                b.nonce = nonce++; block_hash(&b, b.hash); att[m]++; total++;
                if (pow_ok(b.hash, b.difficulty)) { found = 1; winner = m; break; }
            }
    }
    double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;
    scpy(last_mode, sizeof last_mode, "pool");
    commit(&b, &plan, "POOL-OPERATOR");
    summary(&b, total, secs);

    int fee = cfg.block_reward * cfg.pool_fee_pct / 100, dist = cfg.block_reward - fee;
    int reward[POOL_MINERS], paid = 0, top = 0;
    for (int i = 0; i < POOL_MINERS; i++) { reward[i] = (int)((unsigned long)dist * att[i] / total); paid += reward[i]; if (att[i] > att[top]) top = i; }
    reward[top] += dist - paid;                                   /* rounding remainder to the largest contributor */
    printf("  POOL MINING: winner MINER-%d after %lu round(s). Block reward %d, pool fee %d%% = %d, distributable %d\n",
           winner + 1, rounds, cfg.block_reward, cfg.pool_fee_pct, fee, dist);
    printf("  +----------+-----------+----------+-----------+----------+\n");
    printf("  | Miner ID | Hash rate | Attempts | Share %%   | Reward   |\n");
    printf("  +----------+-----------+----------+-----------+----------+\n");
    for (int i = 0; i < POOL_MINERS; i++)
        printf("  | MINER-%-2d | %-9lu | %-8lu | %8.2f%% | %-8d |\n", i + 1, rate[i], att[i], 100.0 * (double)att[i] / (double)total, reward[i]);
    printf("  +----------+-----------+----------+-----------+----------+\n");
    printf("  | POOL-OPERATOR fee (%d%%)                    | %-8d |\n", cfg.pool_fee_pct, fee);
    printf("  +----------------------------------------------+----------+\n");
    for (int i = 0; i < POOL_MINERS; i++) { char id[ID_LEN]; snprintf(id, sizeof id, "MINER-%d", i + 1); credit_miner(id, reward[i], b.index, "MINING"); }
    credit_miner("POOL-OPERATOR", fee, b.index, "POOLFEE");
    print_after_block();
    return 0;
}

/* ---------------------------- CLOUD --------------------------------- */
/*
 * The user rents hash power for 1..5 rounds. Each round the rented rig
 * performs rate = 0.75 * 16^difficulty attempts and costs cloud_fee coins;
 * the reward credited for a round is proportional to the work done:
 * block_reward * attempts_in_round / 16^difficulty (capped at block_reward).
 * Rental stops early when the block is found; if the rental ends first the
 * block is NOT confirmed (fees are still owed) and stays in the pool.
 */
int mine_cloud(int rounds) {
    if (rounds < 1 || rounds > 5) { printf("ERROR: rental duration must be 1 to 5 rounds.\n"); return -1; }
    Block b; BlockPlan plan;
    if (prepare(&b, &plan) == 0) return -1;
    scpy(b.sealed_by, sizeof b.sealed_by, "CLOUD-USER");
    unsigned long target = pow16(b.difficulty), rate = target * 3 / 4;
    if (rate < 1) rate = 1;
    unsigned long total = 0, nonce = (unsigned long)rand();
    int found = 0, gross = 0, fees = 0, used = 0, warned = 0;
    clock_t t0 = clock();
    printf("  CLOUD MINING: renting %d round(s); rig speed %lu attempts/round; fee %d coins/round; max reward %d/round\n", rounds, rate, cfg.cloud_fee, cfg.block_reward);
    printf("  +-------+----------+------+--------+------------+----------+\n");
    printf("  | Round | Attempts | Fee  | Reward | Cum. net   | Status   |\n");
    printf("  +-------+----------+------+--------+------------+----------+\n");
    for (int r = 1; r <= rounds && !found; r++) {
        unsigned long a = 0; used = r;
        for (; a < rate; a++) {
            b.nonce = nonce++; block_hash(&b, b.hash); total++;
            if (pow_ok(b.hash, b.difficulty)) { found = 1; a++; break; }
        }
        unsigned long cap = a > target ? target : a;
        int reward = (int)((unsigned long)cfg.block_reward * cap / target);
        fees += cfg.cloud_fee; gross += reward;
        printf("  | %-5d | %-8lu | %-4d | %-6d | %+-10d | %-8s |\n", r, a, cfg.cloud_fee, reward, gross - fees, found ? "BLOCK!" : "mining");
        if (fees > gross) { printf("  | WARNING: cumulative fees (%d) exceed cumulative rewards (%d) at round %d\n", fees, gross, r); warned = 1; }
    }
    printf("  +-------+----------+------+--------+------------+----------+\n");
    double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;
    printf("  Rounds used: %d of %d rented\n", used, rounds);
    printf("  Gross earnings: %d   Total fees paid: %d   NET PROFIT: %d%s\n", gross, fees, gross - fees, (gross - fees) < 0 ? "  (LOSS)" : "");
    if (warned) printf("  Note: renting was unprofitable at some point; consider fewer rounds or a lower cloud_fee.\n");
    scpy(last_mode, sizeof last_mode, "cloud");
    if (found) {
        commit(&b, &plan, "CLOUD-USER");
        summary(&b, total, secs);
        if (gross - fees > 0) credit_miner("CLOUD-USER", gross - fees, b.index, "CLOUD_NET");
        print_after_block();
    } else {
        snapshot_restore();
        pool_finish(&plan, 0);
        last_attempts = total; last_seconds = secs;
        printf("  Rental ended after %lu attempts without a valid hash - block NOT confirmed; requests stay in the pool.\n", total);
        if (gross - fees > 0) credit_miner("CLOUD-USER", gross - fees, -1, "CLOUD_NET");
    }
    return found ? 0 : -1;
}

void cmd_difficulty_status(void) {
    printf("Difficulty: %d  (valid hash must start with ", cfg.difficulty);
    for (int i = 0; i < cfg.difficulty; i++) putchar('0');
    printf(")\n  expected attempts per block ~ 16^%d = %lu\n", cfg.difficulty, pow16(cfg.difficulty));
    printf("  block reward: %d  batch size: %d records/block  pool fee: %d%%  cloud fee: %d/round  tx fee: %d\n",
           cfg.block_reward, cfg.batch_size, cfg.pool_fee_pct, cfg.cloud_fee, cfg.tx_fee);
    printf("  token model: %s\n", cfg.model == MODEL_UTXO ? "UTXO" : "ACCOUNT");
    if (last_attempts) printf("  last mined block (%s): %lu hash attempts in %.3fs\n", last_mode, last_attempts, last_seconds);
}
