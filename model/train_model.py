from email import policy
from email.parser import BytesParser
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

import joblib


# ============================================================
# 1. PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "datasets"
MODEL_DIR = BASE_DIR / "model"

MODEL_DIR.mkdir(exist_ok=True)


# ============================================================
# 2. READ AN EMAIL
# ============================================================

def read_email(file_path):

    try:

        with open(file_path, "rb") as file:
            message = BytesParser(
                policy=policy.default
            ).parse(file)

        subject = message.get("Subject", "")
        sender = message.get("From", "")
        reply_to = message.get("Reply-To", "")

        body = ""

        if message.is_multipart():

            for part in message.walk():

                if part.get_content_type() == "text/plain":

                    try:
                        body += part.get_content()

                    except Exception:
                        pass

        else:

            try:
                body = message.get_content()

            except Exception:
                pass


        # Combine useful information into one text document
        combined_text = (
            f"SUBJECT: {subject}\n"
            f"FROM: {sender}\n"
            f"REPLY-TO: {reply_to}\n"
            f"BODY: {body}"
        )

        return combined_text


    except Exception as error:

        print(f"Could not parse {file_path}: {error}")

        return None


# ============================================================
# 3. LOAD DATASET
# ============================================================

texts = []
labels = []


print("=" * 60)
print("MAILTRACEAI - DATASET LOADER")
print("=" * 60)


# ------------------------------------------------------------
# HAM DATA
# ------------------------------------------------------------

ham_folders = [
    DATASET_DIR / "easy_ham",
    DATASET_DIR / "hard_ham"
]


for folder in ham_folders:

    if not folder.exists():

        print(f"WARNING: {folder} not found")

        continue


    print(f"\nLoading HAM from: {folder}")

    files = [
        file for file in folder.rglob("*")
        if file.is_file()
    ]

    print(f"Found {len(files)} files")


    for file_path in files:

        text = read_email(file_path)

        if text:

            texts.append(text)
            labels.append("ham")


# ------------------------------------------------------------
# SPAM DATA
# ------------------------------------------------------------

spam_folders = [
    DATASET_DIR / "spam",
    DATASET_DIR / "spam_2"
]


for folder in spam_folders:

    if not folder.exists():

        print(f"WARNING: {folder} not found")

        continue


    print(f"\nLoading SPAM from: {folder}")

    files = [
        file for file in folder.rglob("*")
        if file.is_file()
    ]

    print(f"Found {len(files)} files")


    for file_path in files:

        text = read_email(file_path)

        if text:

            texts.append(text)
            labels.append("spam")


# ============================================================
# 4. CHECK DATASET
# ============================================================

print("\n" + "=" * 60)
print("DATASET SUMMARY")
print("=" * 60)

print("Total emails:", len(texts))
print("HAM:", labels.count("ham"))
print("SPAM:", labels.count("spam"))


if len(texts) < 100:

    raise RuntimeError(
        "Not enough emails found. Check your datasets folder."
    )


# ============================================================
# 5. SPLIT TRAINING AND TEST DATA
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    texts,
    labels,
    test_size=0.20,
    random_state=42,
    stratify=labels
)


print("\nTraining emails:", len(X_train))
print("Testing emails:", len(X_test))


# ============================================================
# 6. BUILD MACHINE LEARNING PIPELINE
# ============================================================

model = Pipeline([

    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            max_features=50000,
            ngram_range=(1, 2)
        )
    ),

    (
        "classifier",
        LogisticRegression(
            max_iter=1000
        )
    )

])


# ============================================================
# 7. TRAIN
# ============================================================

print("\nTraining MailTraceAI model...")

model.fit(X_train, y_train)

print("Training complete!")


# ============================================================
# 8. TEST MODEL
# ============================================================

predictions = model.predict(X_test)


accuracy = accuracy_score(
    y_test,
    predictions
)


print("\n" + "=" * 60)
print("MODEL RESULTS")
print("=" * 60)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions
    )
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)


# ============================================================
# 9. SAVE MODEL
# ============================================================

model_file = MODEL_DIR / "mailtraceai_detector.joblib"

joblib.dump(
    model,
    model_file
)


print("\n" + "=" * 60)

print("MODEL SAVED")

print(model_file)

print("=" * 60)