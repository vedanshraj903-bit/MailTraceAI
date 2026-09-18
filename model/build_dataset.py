"""
Build the MailTraceAI training dataset.

Sources (under datasets/):
    kaggle/**/*.csv             Kaggle CSV datasets         → see KAGGLE_FILES
    custom/ham|spam|phishing/   your own .eml exports       → that label

  with --sources all, also the original downloads:
    easy_ham/, hard_ham/        SpamAssassin public corpus  → ham
    spam/, spam_2/              SpamAssassin public corpus  → spam
    nazario_phishing/*.mbox     Nazario phishing corpus     → phishing

Steps: parse → build model text (model/features.py) → scrub corpus
artifacts → de-duplicate → balance classes → write CSV.

Custom emails are always kept in full and never down-sampled.

Usage:
    python model/build_dataset.py                 # Kaggle only, 2000 per class
    python model/build_dataset.py --sources all   # Kaggle + original corpora
    python model/build_dataset.py --per-class 1800
"""

import argparse
import csv
import hashlib
import json
import mailbox
import random
import re
import sys
from collections import Counter, defaultdict
from email import policy
from email.parser import BytesParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from features import MIN_BODY_CHARS, build_model_text, extract_fields  # noqa: E402


BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "datasets"
OUTPUT_CSV = DATASET_DIR / "mailtrace_dataset.csv"
SUMMARY_JSON = DATASET_DIR / "mailtrace_dataset_summary.json"

LABELS = ("ham", "spam", "phishing")

FOLDER_SOURCES = [
    ("easy_ham", "ham"),
    ("hard_ham", "ham"),
    ("spam", "spam"),
    ("spam_2", "spam"),
]

# Anonymisation placeholders and inbox-owner names baked into the
# public corpora. Left in, the model learns "mentions jose → phishing"
# instead of anything about phishing itself.
CORPUS_ARTIFACTS = re.compile(
    # placeholder domains, also inside fromdomain_/urldomain_ tokens
    # (must come first, or "monkey" alone matches and leaves ".org")
    r"[\w.-]*(?:monkey|taint)[._\s]+org\w*"
    r"|\b(?:jose|nazario|monkey)\b"
    # Enron internal jargon and mailbox owners: every genuine Enron
    # email has them ("hou / ect" routing, HPL pipeline, company name,
    # Vince Kaminski / Daren Farmer whose mailboxes make up the ham)
    r"|\b(?:enron|ect|hou|hpl|kaminski|vince|daren)\b"
    # anonymised names/list tags, e.g. "[zzzzteana]"
    r"|\w*(?:zzzz|yyyy)\w*",
    re.IGNORECASE,
)


# ============================================================
# LOADING
# ============================================================

PARSER = BytesParser(policy=policy.default)


def message_to_text(message):
    fields = extract_fields(message)

    if PLACEHOLDER_SUBJECT.search(fields["subject"]):
        raise ValueError("mbox placeholder record")

    text = build_model_text(**fields)
    return CORPUS_ARTIFACTS.sub(" ", text)


def load_folder(folder, label, source):
    records = []

    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name.startswith("."):
            continue

        try:
            with open(path, "rb") as handle:
                message = PARSER.parse(handle)
            text = message_to_text(message)
        except Exception as error:
            print(f"  skip {path.name}: {error}")
            continue

        records.append({"label": label, "source": source, "text": text})

    return records


def load_mbox(path, label, source):
    records = []

    for raw in mailbox.mbox(str(path), create=False):
        try:
            message = PARSER.parsebytes(raw.as_bytes())
            text = message_to_text(message)
        except Exception:
            continue

        records.append({"label": label, "source": source, "text": text})

    return records


# ============================================================
# KAGGLE CSV DATASETS
# ============================================================
#
# Kaggle "Phishing Email Dataset" (naserabdullahalam/phishing-email-dataset)
# ships one CSV per original corpus with a binary label (1 = bad).
# "Bad" means spam in some corpora and phishing/fraud in others, so
# each file gets its own mapping. Files that duplicate data we
# already load from the original source are skipped.

KAGGLE_FILES = {
    "enron":          {0: "ham", 1: "spam"},
    "ceas_08":        {0: "ham", 1: "spam"},
    "ling":           {0: "ham", 1: "spam"},
    "nigerian_fraud": {1: "phishing"},
    "nazario":        {1: "phishing"},
    "spamassasin":    {0: "ham", 1: "spam"},
    "spamassassin":   {0: "ham", 1: "spam"},
    # merged copy of the files above with spam and phishing collapsed
    # into one label, so it can't train three classes
    "phishing_email": None,
}

# With --sources all these come from the original downloads instead;
# loading both would put the same email in train and test twice.
KAGGLE_COPIES_OF_ORIGINALS = {"nazario", "spamassasin", "spamassassin"}

# mbox bookkeeping records, not real emails
PLACEHOLDER_SUBJECT = re.compile(r"FOLDER INTERNAL DATA", re.IGNORECASE)

# Text labels used by other Kaggle email datasets.
TEXT_LABELS = {
    "ham": "ham", "legit": "ham", "legitimate": "ham", "safe email": "ham",
    "spam": "spam",
    "phishing": "phishing", "phishing email": "phishing", "fraud": "phishing",
}


def _column(row_keys, *candidates):
    lowered = {key.lower().strip(): key for key in row_keys}
    for candidate in candidates:
        if candidate in lowered:
            return lowered[candidate]
    return None


def load_kaggle_csv(path, include_original_copies=True):
    """
    Load one Kaggle CSV. Returns (records, note) where note explains
    a skip.
    """

    stem = path.stem.lower()

    if stem in KAGGLE_FILES and KAGGLE_FILES[stem] is None:
        return [], "skipped (merged copy, spam and phishing not separated)"

    if stem in KAGGLE_COPIES_OF_ORIGINALS and not include_original_copies:
        return [], "skipped (original corpus loaded instead)"

    mapping = KAGGLE_FILES.get(stem)

    csv.field_size_limit(sys.maxsize)

    with open(path, newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        keys = reader.fieldnames or []

        body_col = _column(keys, "body", "text", "email text", "message", "content")
        subject_col = _column(keys, "subject")
        sender_col = _column(keys, "sender", "from")
        label_col = _column(keys, "label", "email type", "class", "category")

        if not body_col or not label_col:
            return [], f"skipped (no body/label column in {keys})"

        records = []

        for row in reader:
            raw_label = str(row.get(label_col, "")).strip().lower()

            if mapping is not None:
                try:
                    label = mapping.get(int(float(raw_label)))
                except ValueError:
                    label = None
            else:
                label = TEXT_LABELS.get(raw_label)

            if label is None:
                continue

            subject = row.get(subject_col, "") if subject_col else ""

            if PLACEHOLDER_SUBJECT.search(subject or ""):
                continue

            text = build_model_text(
                subject=subject,
                sender=row.get(sender_col, "") if sender_col else "",
                plain_text=row.get(body_col, "") or "",
            )

            records.append({
                "label": label,
                "source": f"kaggle_{stem}",
                "text": CORPUS_ARTIFACTS.sub(" ", text),
            })

    return records, ""


def load_all(sources="kaggle"):
    records = []
    use_originals = sources == "all"

    if use_originals:
        for folder_name, label in FOLDER_SOURCES:
            folder = DATASET_DIR / folder_name
            if folder.exists():
                found = load_folder(folder, label, folder_name)
                print(f"{folder_name:<22} {label:<9} {len(found):>5}")
                records += found

        for path in sorted((DATASET_DIR / "nazario_phishing").glob("*.mbox")):
            source = "nazario_" + path.stem.replace("phishing-", "")
            found = load_mbox(path, "phishing", source)
            print(f"{source:<22} {'phishing':<9} {len(found):>5}")
            records += found

    kaggle_files = sorted((DATASET_DIR / "kaggle").rglob("*.csv"))

    if not kaggle_files:
        print("WARNING: no CSV files in datasets/kaggle/")

    for path in kaggle_files:
        found, note = load_kaggle_csv(path, include_original_copies=not use_originals)
        counts = Counter(r["label"] for r in found)
        summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        print(f"{'kaggle_' + path.stem.lower():<22} {note or summary}")
        records += found

    for label in LABELS:
        folder = DATASET_DIR / "custom" / label
        if folder.exists():
            found = load_folder(folder, label, f"custom_{label}")
            if found:
                print(f"{'custom/' + label:<22} {label:<9} {len(found):>5}")
            records += found

    return records


# ============================================================
# CLEANING
# ============================================================

def body_of(text):
    return text.split("BODY:", 1)[-1].strip()


def deduplicate(records):
    """
    Drop exact duplicates (same model text). If the same text
    appears under different labels, drop every copy: it is
    unlearnable and would leak between train and test.
    """

    by_hash = defaultdict(list)

    for record in records:
        key = hashlib.sha1(record["text"].lower().encode("utf-8")).hexdigest()
        record["id"] = key[:16]
        by_hash[key].append(record)

    kept = []
    conflicts = 0

    for group in by_hash.values():
        if len({record["label"] for record in group}) > 1:
            conflicts += 1
            continue
        kept.append(group[0])

    return kept, len(records) - len(kept), conflicts


# ============================================================
# BALANCING
# ============================================================

def sample_evenly_by_source(records, target, rng):
    """
    Take `target` records, spreading them across sources so no
    single year / folder dominates. Custom records are always kept.
    """

    custom = [r for r in records if r["source"].startswith("custom_")]
    public = [r for r in records if not r["source"].startswith("custom_")]

    remaining = max(target - len(custom), 0)

    if len(public) <= remaining:
        return custom + public

    by_source = defaultdict(list)
    for record in public:
        by_source[record["source"]].append(record)

    for group in by_source.values():
        rng.shuffle(group)

    # Round-robin over sources until the quota is filled.
    chosen = []
    sources = sorted(by_source)

    while len(chosen) < remaining:
        for source in sources:
            if by_source[source] and len(chosen) < remaining:
                chosen.append(by_source[source].pop())

    return custom + chosen


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--per-class", type=int, default=2000,
                        help="target emails per label (default 2000 → ~6000 rows)")
    parser.add_argument("--sources", choices=["kaggle", "all"], default="kaggle",
                        help="kaggle: only datasets/kaggle (+ custom); "
                             "all: also the original SpamAssassin/Nazario downloads")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)

    print("=" * 60)
    print("LOADING SOURCES")
    print("=" * 60)

    records = load_all(args.sources)

    records = [r for r in records if len(body_of(r["text"])) >= MIN_BODY_CHARS]

    records, removed, conflicts = deduplicate(records)

    print(f"\nRemoved {removed} duplicate/empty-conflict rows "
          f"({conflicts} texts had conflicting labels)")

    dataset = []

    for label in LABELS:
        pool = [r for r in records if r["label"] == label]
        picked = sample_evenly_by_source(pool, args.per_class, rng)
        dataset += picked
        print(f"{label:<9} available {len(pool):>5}  →  using {len(picked):>5}")

    rng.shuffle(dataset)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "label", "source", "text"])
        writer.writeheader()
        writer.writerows(dataset)

    summary = {
        "rows": len(dataset),
        "per_label": Counter(r["label"] for r in dataset),
        "per_source": Counter(r["source"] for r in dataset),
        "per_class_target": args.per_class,
        "sources_mode": args.sources,
        "seed": args.seed,
        "sources": {
            "kaggle": "https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset",
            **({
                "spamassassin": "https://spamassassin.apache.org/old/publiccorpus/",
                "nazario_phishing": "https://monkey.org/~jose/phishing/ (CC-BY-4.0, Jose Nazario)",
            } if args.sources == "all" else {}),
        },
    }

    SUMMARY_JSON.write_text(json.dumps(summary, indent=2, sort_keys=True))

    print("\n" + "=" * 60)
    print(f"WROTE {len(dataset)} rows → {OUTPUT_CSV.relative_to(BASE_DIR)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
