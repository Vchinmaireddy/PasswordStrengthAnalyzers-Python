#!/usr/bin/env python3
"""Command-line interface for the Password Strength Analyzer.

  python cli.py analyze [--breach] [--json] [--info NAME ...]
  python cli.py generate [--length 16] [--no-symbols] ... | --passphrase --words 5
  python cli.py audit passwords.txt [--out report.csv]
"""
import argparse
import getpass
import sys

from psa import breach, generator, report
from psa.engine import PasswordAnalyzer


def cmd_analyze(args):
    pw = sys.stdin.readline().rstrip("\n") if args.stdin else getpass.getpass("Password (hidden): ")
    count = None
    if args.breach:
        try:
            count = breach.pwned_count(pw)
        except breach.BreachCheckError as exc:
            print(f"[!] {exc}", file=sys.stderr)
    result = PasswordAnalyzer().analyze(pw, personal_info=args.info, breach_count=count)
    print(report.to_json(result) if args.json else report.to_text(result))


def cmd_generate(args):
    if args.passphrase:
        pw = generator.generate_passphrase(args.words, args.separator, args.capitalize, args.number)
        bits = generator.passphrase_entropy(args.words, args.number)
    else:
        opts = dict(lower=not args.no_lower, upper=not args.no_upper,
                    digits=not args.no_digits, symbols=not args.no_symbols,
                    exclude_ambiguous=args.no_ambiguous)
        pw = generator.generate_password(args.length, **opts)
        bits = generator.password_entropy(args.length, **opts)
    print(pw)
    print(f"(~{bits:.0f} bits of entropy)", file=sys.stderr)


def cmd_audit(args):
    rows = report.audit_file(args.file)
    s = report.summarize(rows)
    print(f"Audited {s['total']} passwords: {s['weak_percent']}% weak, {s['duplicates']} duplicates")
    for level, n in sorted(s["levels"].items(), key=lambda kv: -kv[1]):
        print(f"  {level:12} {n}")
    if args.out:
        report.write_audit_csv(rows, args.out)
        print(f"Report written to {args.out} (no plain-text passwords included)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze"); a.set_defaults(func=cmd_analyze)
    a.add_argument("--breach", action="store_true", help="check Have I Been Pwned (k-anonymity)")
    a.add_argument("--json", action="store_true"); a.add_argument("--stdin", action="store_true")
    a.add_argument("--info", nargs="*", default=[], help="personal info words to detect")
    g = sub.add_parser("generate"); g.set_defaults(func=cmd_generate)
    g.add_argument("--length", type=int, default=16)
    for flag in ("lower", "upper", "digits", "symbols", "ambiguous"):
        g.add_argument(f"--no-{flag}", action="store_true")
    g.add_argument("--passphrase", action="store_true"); g.add_argument("--words", type=int, default=5)
    g.add_argument("--separator", default="-"); g.add_argument("--capitalize", action="store_true")
    g.add_argument("--number", action="store_true")
    u = sub.add_parser("audit"); u.set_defaults(func=cmd_audit)
    u.add_argument("file"); u.add_argument("--out")
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
