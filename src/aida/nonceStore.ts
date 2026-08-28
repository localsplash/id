import type mysql from "mysql2/promise";
import { NonceStore } from "./service";

/**
 * Replay guard backed by MySQL rather than process memory: replicas share one
 * table, so a request replayed against a second instance is still refused.
 *
 * The insert is the check. `INSERT IGNORE` on a primary key is atomic, so two
 * instances racing on the same nonce cannot both see it as fresh — which a
 * read-then-write would allow.
 */
export class MysqlNonceStore implements NonceStore {
  private lastPrune = 0;

  constructor(private pool: mysql.Pool) {}

  async consume(nonce: string, expiresAt: Date): Promise<boolean> {
    const [result] = await this.pool.query<mysql.ResultSetHeader>(
      "INSERT IGNORE INTO id_tbl_AidaNonce (sNonce, dtExpires) VALUES (?, ?)",
      [nonce, expiresAt],
    );
    void this.prune();
    return result.affectedRows === 1;
  }

  /** Expired rows are dead weight; sweep them at most once a minute. */
  private async prune(): Promise<void> {
    const now = Date.now();
    if (now - this.lastPrune < 60_000) return;
    this.lastPrune = now;
    try {
      await this.pool.query(
        "DELETE FROM id_tbl_AidaNonce WHERE dtExpires < NOW(3)",
      );
    } catch {
      // Housekeeping only — never fail a request because the sweep did not run.
    }
  }
}
