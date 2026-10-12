# commands/export.py
"""export command — export a specific scan to reports."""

import sys
import logging

from database import DatabaseManager
from report_generator import ReportGenerator

logger = logging.getLogger(__name__)


def cmd_export(args, config):
    db = DatabaseManager(config["database"]["path"])
    data = db.get_scan_data(args.scan_id)

    if not data.get("scan_info"):
        logger.error(f"Scan ID {args.scan_id} not found.")
        sys.exit(3)

    report_path = ReportGenerator.generate(
        data,
        config["reporting"]["output_dir"],
        "EXPORT"
    )
    print(f"Exported to: {report_path}")
