from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from pathlib import Path
import shutil
import uuid

from orchestrator import run_pipeline


app = FastAPI(
    title="MailTraceAI API",
    description="AI-powered email threat detection and forensic intelligence platform",
    version="1.2"
)


# --------------------------------------------------
# CORS CONFIGURATION
# --------------------------------------------------

ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --------------------------------------------------
# UPLOAD DIRECTORY
# --------------------------------------------------

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


# --------------------------------------------------
# FORENSIC REPORT FILE
# --------------------------------------------------

REPORT_FILE = Path("forensic_report.html")


# --------------------------------------------------
# ROOT ENDPOINT
# --------------------------------------------------

@app.get("/")
def root():
    return {
        "tool": "MailTraceAI",
        "status": "ONLINE",
        "version": "1.2"
    }


# --------------------------------------------------
# EMAIL ANALYSIS ENDPOINT
# --------------------------------------------------

@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):

    # --------------------------------------------------
    # 1. VALIDATE FILE
    # --------------------------------------------------

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file was provided."
        )

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml email files are supported."
        )


    # --------------------------------------------------
    # 2. CREATE SAFE TEMPORARY FILENAME
    # --------------------------------------------------

    safe_filename = f"{uuid.uuid4().hex}.eml"

    file_path = UPLOAD_DIR / safe_filename


    try:

        # --------------------------------------------------
        # 3. SAVE UPLOADED EMAIL
        # --------------------------------------------------

        with file_path.open("wb") as buffer:

            shutil.copyfileobj(
                file.file,
                buffer
            )


        # --------------------------------------------------
        # 4. RUN COMPLETE MAILTRACEAI PIPELINE
        # --------------------------------------------------

        result = run_pipeline(
            file_path
        )


        # --------------------------------------------------
        # 5. RETURN ANALYSIS
        # --------------------------------------------------

        return result


    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {str(e)}"
        )


    finally:

        # --------------------------------------------------
        # 6. DELETE TEMPORARY EMAIL
        # --------------------------------------------------

        if file_path.exists():

            file_path.unlink()


# --------------------------------------------------
# FORENSIC REPORT ENDPOINT
# --------------------------------------------------

@app.get("/report")
def get_forensic_report():

    """
    Return the most recently generated MailTraceAI
    forensic HTML report.
    """

    if not REPORT_FILE.exists():

        raise HTTPException(
            status_code=404,
            detail="Forensic report has not been generated yet."
        )


    return FileResponse(
        path=REPORT_FILE,
        media_type="text/html",
        filename="forensic_report.html"
    )