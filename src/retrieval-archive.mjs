function merge(db, row) {
  const key = [row.revision, row.origin, row.mode];
  const old = db.prepare('SELECT * FROM retrieval_archive WHERE revision=? AND origin=? AND mode=?').get(...key);
  const metrics = old ? JSON.parse(old.value) : {};
  for (const [name, value] of Object.entries(JSON.parse(row.value))) metrics[name] = (metrics[name] ?? 0) + value;
  db.prepare('INSERT OR REPLACE INTO retrieval_archive VALUES(?,?,?,?,?,?)')
    .run(...key, (old?.samples ?? 0) + (row.samples ?? 1), Math.max(old?.at ?? 0, row.at), JSON.stringify(metrics));
}

// Called inside the writer transaction: detail removal cannot lose its totals.
export function archiveRetrieval(db) {
  const cutoff = Date.now() - 30 * 86400000;
  const condition = 'at < ? OR id NOT IN (SELECT id FROM retrieval_metrics ORDER BY id DESC LIMIT 10000)';
  for (const row of db.prepare(`SELECT * FROM retrieval_metrics WHERE ${condition}`).all(cutoff)) merge(db, row);
  db.prepare(`DELETE FROM retrieval_metrics WHERE ${condition}`).run(cutoff);
  // Preserve totals, but deliberately stop claiming exact revision attribution
  // for old cohorts beyond the bounded archive. Origins remain separate.
  const old = db.prepare("SELECT * FROM retrieval_archive WHERE revision!='archived' ORDER BY at DESC LIMIT -1 OFFSET 128").all();
  for (const row of old) {
    merge(db, { ...row, revision: 'archived' });
    db.prepare('DELETE FROM retrieval_archive WHERE revision=? AND origin=? AND mode=?').run(row.revision, row.origin, row.mode);
  }
}
