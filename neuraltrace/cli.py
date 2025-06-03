# neuraltrace/cli.py
"""
Command-line interface for NeuralTrace.
Handles user interactions.
"""
import asyncio
import argparse
import logging
from neuraltrace.main import NeuralTrace

logger = logging.getLogger(__name__)

def setup_cli():
    """Set up CLI parser."""
    parser = argparse.ArgumentParser(description="NeuralTrace: RAG-Backed LLM Network Forensic Tool")
    parser.add_argument("--interface", required=True, help="Network interface (e.g., eth0)")
    parser.add_argument("--count", type=int, default=100, help="Number of packets to capture")
    parser.add_argument("--x-handle", help="X username for OSINT")
    parser.add_argument("--init-db", action="store_true", help="Initialize database")
    parser.add_argument("--report", default="neuraltrace_report.jsonl", help="Report file")
    return parser.parse_args()

async def run_cli():
    """Run CLI commands."""
    args = setup_cli()
    trace = NeuralTrace(args.interface)
    
    if args.init_db:
        await trace.db._init_db()
        logger.info("Database initialized")
    else:
        result = await trace.run_analysis(args.count, args.x_handle)
        await trace.save_report(args.report)
        logger.info(f"Analysis completed. Report saved to {args.report}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    asyncio.run(run_cli())