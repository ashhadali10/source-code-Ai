# commands/history.py
"""history command — view scan history."""

import logging

from database import DatabaseManager

logger = logging.getLogger(__name__)


def cmd_history(args, config):
    db = DatabaseManager(config["database"]["path"])
    conn = db._get_conn()

    finding_id = getattr(args, "finding_id", None)

    if finding_id:
        cursor = conn.execute(
            "SELECT * FROM finding_history WHERE finding_id = ? ORDER BY timestamp DESC",
            (finding_id,)
        )
    else:
        cursor = conn.execute(
            "SELECT * FROM finding_history ORDER BY timestamp DESC LIMIT 50"
        )

    print(f"\n{'Finding ID':<20} | {'Event':<12} | {'Old Status':<18} | {'New Status':<18} | {'Date'}")
    print("-" * 110)

    rows = cursor.fetchall()
    if not rows:
        print("(no history yet)")
    for row in rows:
        print(
            f"{row['finding_id']:<20} | {row['event_type']:<12} | "
            f"{str(row['old_status'] or 'N/A'):<18} | "
            f"{str(row['new_status'] or 'N/A'):<18} | {row['timestamp']}"
        )

    conn.close()
