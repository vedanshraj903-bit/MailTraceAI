# Your own training emails

Drop `.eml` files into the folder that matches what they are:

| Folder | Put here |
|---|---|
| `ham/` | Genuine email: real bank alerts, OTPs, receipts, newsletters, work and personal mail |
| `spam/` | Unwanted marketing / junk that isn't trying to steal anything |
| `phishing/` | Emails trying to steal credentials, money or data (fake KYC, fake bank, fake courier, fake login pages) |

**Gmail:** open the email → ⋮ → *Download message*.
**Outlook:** open the email → … → *Save as* (.eml).

Then rebuild and retrain:

```
.venv/bin/python model/build_dataset.py
.venv/bin/python model/train_model.py
```

Custom emails are always kept in full, never down-sampled, and show up as
`custom_ham` / `custom_spam` / `custom_phishing` in the per-source results.

The Kaggle training data is from 2000–2008 (ham/spam) and up to 2022
(phishing), so **modern genuine email in `ham/` improves the model the most**. Remove personal
details before sharing these files or committing them to git.
