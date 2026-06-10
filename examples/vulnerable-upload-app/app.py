from flask import Flask, request

app = Flask(__name__)

FAKE_API_KEY = "api_key_demo_1234567890abcdef"
DATABASE_ROWS = []


@app.post("/upload")
def upload():
    files = request.files.getlist("files")
    for file in files:
        DATABASE_ROWS.append({
            "filename": file.filename,
            "data": file.read(),
        })
    return {"saved": len(files)}


@app.get("/")
def index():
    return "demo vulnerable upload app"

