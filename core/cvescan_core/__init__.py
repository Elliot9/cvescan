"""cvescan core: deterministic detect / sync / scan / verify / status.

No AI is involved anywhere in this package. The AI only ever reads the files
this package writes (report.json, sbom.cdx.json, ANALYZE.md) and hands back an
analysis.json, which `verify` checks with plain rules.
"""

__version__ = "0.1.0"
