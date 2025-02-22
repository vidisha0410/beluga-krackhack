from fastapi import FastAPI, File, UploadFile
import os
import yara
import pefile

app = FastAPI()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Load YARA rules (Placeholder - replace with actual rules)
RULES = yara.compile(source="""
rule SuspiciousString
{
    strings:
        $a = "malware"
    condition:
        $a
}
""")

@app.post("/scan/")
async def scan_file(file: UploadFile = File(...)):
    """Handle file uploads and scan for malware indicators."""
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    
    with open(file_path, "wb") as f:
        f.write(await file.read())
    
    # Perform YARA scan
    matches = RULES.match(file_path)
    
    # Perform PE file analysis (if executable)
    pe_info = None
    if file.filename.endswith(".exe"):
        try:
            pe = pefile.PE(file_path)
            pe_info = {"sections": [section.Name.decode().strip() for section in pe.sections]}
        except Exception as e:
            pe_info = {"error": str(e)}

    verdict = "Malicious" if matches else "Clean"

    return {
        "filename": file.filename,
        "verdict": verdict,
        "yara_matches": [match.rule for match in matches],
        "pe_info": pe_info
    }

