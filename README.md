# 🔐 Password Strength Analyzer v2.0

A cybersecurity tool (Python + Tkinter, standard library only) that does not just count character
types - it estimates **how long a real attacker would need** to crack a password, explains *why* it
is weak, and helps you create a better one.

![Analyzer](screenshots/01_analyzer_weak.png)

## Features

| Area | What it does |
|---|---|
| **Pattern-aware entropy** | Finds dictionary words, leetspeak (`p@ssw0rd`), reversed words, keyboard walks (`qwerty`, `1qaz2wsx`), sequences, repeats, dates/years and personal info, then picks the cheapest way an attacker could build the password (dynamic programming). |
| **Ranked wordlists** | 10,000 most common leaked passwords + 10,000 English words + 7,776 EFF words; rarer words cost more "guess bits". |
| **Crack-time estimates** | Online (throttled / unthrottled) and offline (slow hash / GPU fast hash) scenarios. |
| **Breach check** | Have I Been Pwned *k-anonymity* API - only the first 5 hex chars of the SHA-1 leave your PC. |
| **Live feedback** | Re-analyzes as you type, colored meter, security checklist, plain-English suggestions. |
| **Generator** | `secrets`-based passwords (length, character classes, no look-alikes) and EFF passphrases; clipboard auto-clears after 30 s. |
| **Reuse detection** | Salted **PBKDF2-HMAC-SHA256** (200,000 iterations) fingerprints in SQLite - plain-text passwords are never stored. |
| **Batch audit** | Analyze a file of passwords, see weak % and duplicates, export CSV (line numbers only, no passwords). |
| **Reports** | Export TXT / JSON - reports never contain any part of the password. |
| **Themes** | 5 built-in themes (Dark Slate, Light, Cyberpunk, Hacker Green, Sunset) - switch live from the *Theme* box; your choice is remembered. |
| **CLI** | `analyze`, `generate`, `audit` for scripting. |
| **Tests** | 34 unit tests (`python -m unittest discover -s tests -t .`). |

## Run it

```bash
python main.py                      # GUI  (Python 3.10+)
python cli.py analyze --breach      # hidden prompt, optional breach lookup
python cli.py generate --length 20
python cli.py generate --passphrase --words 6 --capitalize
python cli.py audit data/sample_passwords.txt --out audit.csv
python -m unittest discover -s tests -t .
```

## How the score is calculated

1. Build every pattern match inside the password (word, leet, keyboard, sequence, repeat, date, personal).
2. Each match has a cost in bits, e.g. a dictionary word costs `log2(rank)` bits, a keyboard walk about
   `log2(47) + 1.6 × steps`, unmatched characters cost `log2(charset size)` each.
3. Dynamic programming chooses the **cheapest decomposition** → *effective entropy*.
4. `guesses ≈ 2^(bits-1)`; crack time = guesses ÷ attacker speed.
5. `score = min(100, 1.125 × bits)`; levels: <30 Very Weak · <50 Weak · <70 Medium · <90 Strong · ≥90 Very Strong.
   Passwords under 8 characters are capped at Weak, common/breached passwords at Very Weak.

> The checklist for upper/lower/digit/symbol becomes *optional* once entropy is high - current NIST
> guidance (SP 800-63B) values length and blocklists over composition rules.

## What changed from v1

| v1 prototype | v2 |
|---|---|
| Entropy = length × log2(charset) (a password like `Password1!` looked strong) | Pattern-aware effective entropy |
| 15 hard-coded common passwords | 10k ranked leaked passwords + 10k words + leet/reverse handling |
| `"123"`, `"abc"`, `"qwerty"` only | General sequence, keyboard-walk, repeat, date and personal-info detection |
| Unsalted SHA-256 history, **every analyzed password was saved** | Salted PBKDF2 (200k iter.), saved only on request, plus labels, delete & clear |
| Text-only report | Meter, checklist, crack times, findings, suggestions, export |
| GUI started on import; relative file paths broke when run from another folder | Modular package, `if __name__ == "__main__"`, absolute data paths |
| No generator options | Length/classes/look-alikes, passphrases, clipboard auto-clear |
| No tests, empty `requirements.txt` | 34 unit tests, CLI, batch audit, breach API |

## Project structure

```
PasswordStrengthAnalyzer/
├── main.py              # GUI launcher
├── cli.py               # command-line interface
├── psa/
│   ├── engine.py        # analysis engine (entropy, patterns, scoring, crack times)
│   ├── generator.py     # secure password / passphrase generator
│   ├── storage.py       # salted-hash history (SQLite)
│   ├── breach.py        # Have I Been Pwned k-anonymity lookup
│   ├── report.py        # TXT/JSON export + batch audit
│   ├── themes.py        # colour themes + saved choice
│   └── gui.py           # Tkinter interface
├── data/                # wordlists + sample_passwords.txt
├── tests/               # unittest suite
└── screenshots/
```

## Limitations

* Estimates are **models, not guarantees** - real attackers vary and dictionaries are finite
  (e.g. a rare word with leetspeak may be missed).
* The breach check needs an internet connection; everything else works offline.
* Use a password manager and two-factor authentication - the best password is one you never memorize or reuse.

## Credits & licences of data

* Common passwords: [SecLists](https://github.com/danielmiessler/SecLists) `10k-most-common.txt` (MIT).
* English words: [google-10000-english](https://github.com/first20hours/google-10000-english).
* Passphrase words: EFF Large Wordlist (CC BY 3.0 US), via the `xkcdpass` package.
* Breach data: [Have I Been Pwned - Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords).
* v2 is a rewrite of an earlier Tkinter prototype (original README credited *Pinninti Deekshith Reddy*).

## Disclaimer

For education, security awareness and defensive use only. Only audit passwords you own or are authorized to test.
