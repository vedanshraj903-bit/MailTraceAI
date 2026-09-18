# MailTraceAI detector — model card

Classifies an email as **ham** (genuine), **spam** or **phishing**.

## Pipeline

```
datasets/  ──build_dataset.py──►  datasets/mailtrace_dataset.csv  ──train_model.py──►  mailtraceai_detector.joblib
                                                                                     mailtraceai_detector.json (metadata)
```

`features.py` turns an email into the text the model sees. Training and the
live app (`Risk/risk_engine.py`, `predict_email.py`) both use it, so they
always see emails the same way.

- HTML-only bodies are converted to text; link targets are kept.
- URLs become `urltoken urldomain_<domain>` (or `urlipaddress` for raw IPs).
- Email addresses, years and long numbers become placeholder tokens so the
  model learns patterns, not specific strings or the era of a corpus.
- The sender's domain is **not** a feature (it mostly encoded the era of the
  data, e.g. Gmail didn't exist in 2002). A Reply-To domain mismatch is.

## Data

Default: **Kaggle only** — "Phishing Email Dataset" by Naser Abdullah Alam
(<https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset>),
CSV files unzipped into `datasets/kaggle/`. Check the licence on the Kaggle
page before commercial use.

| File | Used as | Era |
|---|---|---|
| `Enron.csv` | ham / spam | 2000–2005 |
| `CEAS_08.csv` | ham / spam | 2008 |
| `Ling.csv` | ham / spam | ~2000 |
| `SpamAssasin.csv` | ham / spam | 2002–2005 |
| `Nazario.csv` | phishing | 2015–2022 |
| `Nigerian_Fraud.csv` | phishing (advance-fee scams) | 1998–2007 |
| `phishing_email.csv` | skipped — merged copy with spam and phishing in one label | |
| `datasets/custom/<label>/` | your own `.eml` exports, always included | |

`build_dataset.py` decodes encoded headers, removes duplicates and bodies under
40 characters, scrubs corpus giveaways (inbox-owner names, placeholder
domains, list tags, Enron jargon and mailbox owners), drops mbox placeholder
records, and balances to 2,000 emails per label (6,000 rows; `--per-class` to
change), spread evenly across sources.

`--sources all` also loads the original SpamAssassin folders and the Nazario
2015–2025 mbox downloads (and then skips the Kaggle copies of those two).

## Model

Word 1–2-grams + character 3–5-grams (TF-IDF, sublinear) → logistic regression
with balanced class weights. `C` and word n-gram range are chosen by 5-fold
cross-validated grid search on the training split (macro-F1).

## Results (held-out 20% test split, Kaggle-only model)

| | precision | recall | F1 |
|---|---|---|---|
| ham | 0.977 | 0.963 | 0.970 |
| spam | 0.960 | 0.950 | 0.955 |
| phishing | 0.966 | 0.990 | 0.978 |

Accuracy 0.968 · macro-F1 0.967 · 5-fold CV macro-F1 0.972 · ham false-positive
rate 3.8%. Full numbers, per-source accuracy and top features are in
`mailtraceai_detector.json` after each run.

### Beyond the test split

- **2,400 unseen Kaggle emails** (CEAS, Enron, Ling, Nigerian fraud):
  accuracy 0.964, genuine wrongly flagged 3.2%, spam caught 94.5%,
  scams caught 99.0%.
- **Phishing from after the training data** (Nazario 2023–2025, 1,290 emails,
  none seen in training): 89–91% classified as phishing, 95–97% flagged as
  not genuine.

## Known limitations

- **Genuine email in the training data is 2000–2008** (SpamAssassin, Enron,
  CEAS, Ling). Modern genuine email — bank alerts, OTPs, receipts — is
  under-represented. Adding your own to `datasets/custom/ham/` helps most.
- **Half of the phishing class is advance-fee scams**, the other half comes
  from one person's inbox up to 2022, so lures targeting other regions (e.g.
  Indian banks, UPI, KYC) are under-represented. Add examples to
  `datasets/custom/phishing/`.
- The app ignores the model for bodies under 40 characters (too little text).
- Scores on this test split are optimistic for real-world use: train and
  test come from the same corpora.

## Retrain

```
.venv/bin/python model/build_dataset.py
.venv/bin/python model/train_model.py          # ~2–3 min, full grid search
.venv/bin/python model/train_model.py --quick  # ~20 s, single config
.venv/bin/python model/predict_email.py path/to/email.eml
```

Restart the backend afterwards so it loads the new model.
