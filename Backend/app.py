from datetime import datetime
import os
import threading
import traceback
import uuid

from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from werkzeug.utils import secure_filename

from parser import AnalysisCancelled, analyze_log_file, save_report


app = Flask(__name__)
CORS(app)

UPLOAD_DIR = "uploads"
REPORT_DIR = "job_results"

MAX_UPLOAD_MB = 1100
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

ALLOWED_LOG_TYPES = {".log", ".txt"}

running_jobs = {}

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


def is_log_file(filename):
    extension = os.path.splitext(filename.lower())[1]
    return extension in ALLOWED_LOG_TYPES


def create_analysis_job(source_name):
    job_id = str(uuid.uuid4())

    running_jobs[job_id] = {
        "job_id": job_id,
        "source_name": source_name,
        "status": "queued",
        "progress": 0,
        "message": "Waiting to start",
        "created_at": datetime.now().isoformat(),
        "completed_at": None,
        "report": None,
        "error": None,
        "cancel_requested": False
    }

    return job_id


def job_was_cancelled(job_id):
    job = running_jobs.get(job_id)

    if job is None:
        return True

    return job.get("cancel_requested", False)


def delete_file_quietly(file_path):
    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
    except OSError:
        pass


def update_analysis_progress(job_id, processed_bytes, total_bytes):
    if job_was_cancelled(job_id):
        return

    if total_bytes <= 0:
        progress = 10
    else:
        progress = int(10 + ((processed_bytes / total_bytes) * 80))

    progress = max(10, min(progress, 90))

    running_jobs[job_id]["progress"] = progress
    running_jobs[job_id]["message"] = f"Parsing log file ({progress}%)"


def mark_job_cancelled(job_id, file_path=None):
    running_jobs[job_id]["status"] = "cancelled"
    running_jobs[job_id]["progress"] = 100
    running_jobs[job_id]["message"] = "Job cancelled"
    running_jobs[job_id]["completed_at"] = datetime.now().isoformat()
    running_jobs[job_id]["report"] = None
    running_jobs[job_id]["error"] = None

    delete_file_quietly(file_path)


def run_log_analysis(job_id, file_path):
    try:
        if job_was_cancelled(job_id):
            raise AnalysisCancelled("Job cancelled")

        running_jobs[job_id]["status"] = "processing"
        running_jobs[job_id]["progress"] = 5
        running_jobs[job_id]["message"] = "Starting parser"

        report = analyze_log_file(
            file_path,
            show_progress=True,
            progress_callback=lambda done, total: update_analysis_progress(
                job_id,
                done,
                total
            ),
            cancel_check=lambda: job_was_cancelled(job_id)
        )

        if job_was_cancelled(job_id):
            raise AnalysisCancelled("Job cancelled")

        running_jobs[job_id]["progress"] = 95
        running_jobs[job_id]["message"] = "Saving report"

        report_path = os.path.join(REPORT_DIR, f"{job_id}.json")
        save_report(report, report_path)

        running_jobs[job_id]["status"] = "completed"
        running_jobs[job_id]["progress"] = 100
        running_jobs[job_id]["message"] = "Analysis complete"
        running_jobs[job_id]["completed_at"] = datetime.now().isoformat()
        running_jobs[job_id]["report"] = report

    except AnalysisCancelled:
        mark_job_cancelled(job_id, file_path)

    except Exception as error:
        running_jobs[job_id]["status"] = "failed"
        running_jobs[job_id]["progress"] = 100
        running_jobs[job_id]["message"] = "Analysis failed"
        running_jobs[job_id]["error"] = str(error)

        print("LogLens job failed")
        print(traceback.format_exc())


@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "error": f"File is too large. Upload limit is {MAX_UPLOAD_MB} MB."
    }), 413


@app.route("/")
def home():
    return jsonify({
        "message": "LogLens backend is running",
        "upload_limit_mb": MAX_UPLOAD_MB,
        "endpoints": [
            "/analyze-sample",
            "/start-sample-job",
            "/upload",
            "/upload-async",
            "/cancel-job/<job_id>",
            "/job-status/<job_id>"
        ]
    })


@app.route("/analyze-sample", methods=["GET"])
def analyze_sample_log():
    report = analyze_log_file("sample.log")
    save_report(report)

    return jsonify(report)


@app.route("/start-sample-job", methods=["GET", "POST"])
def start_sample_job():
    job_id = create_analysis_job("sample.log")

    analysis_thread = threading.Thread(
        target=run_log_analysis,
        args=(job_id, "sample.log"),
        daemon=True
    )

    analysis_thread.start()

    return jsonify({
        "job_id": job_id,
        "status": running_jobs[job_id]["status"],
        "message": "Sample log job started"
    })


@app.route("/upload-page")
def upload_test_page():
    return render_template_string("""
    <h1>LogLens Upload Test</h1>

    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" accept=".log,.txt">
        <button type="submit">Upload and Analyze</button>
    </form>
    """)


@app.route("/upload", methods=["POST"])
def upload_log_file_sync():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if not is_log_file(uploaded_file.filename):
        return jsonify({"error": "Only .log and .txt files are allowed"}), 400

    safe_name = secure_filename(uploaded_file.filename)
    saved_path = os.path.join(UPLOAD_DIR, safe_name)

    uploaded_file.save(saved_path)

    report = analyze_log_file(saved_path)
    save_report(report)

    return jsonify(report)


@app.route("/upload-async", methods=["POST"])
def upload_log_file_async():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if not is_log_file(uploaded_file.filename):
        return jsonify({"error": "Only .log and .txt files are allowed"}), 400

    job_id = create_analysis_job(uploaded_file.filename)

    safe_name = secure_filename(uploaded_file.filename)
    stored_name = f"{job_id}_{safe_name}"
    saved_path = os.path.join(UPLOAD_DIR, stored_name)

    uploaded_file.save(saved_path)

    analysis_thread = threading.Thread(
        target=run_log_analysis,
        args=(job_id, saved_path),
        daemon=True
    )

    analysis_thread.start()

    return jsonify({
        "job_id": job_id,
        "status": running_jobs[job_id]["status"],
        "message": "Upload received"
    })


@app.route("/cancel-job/<job_id>", methods=["POST"])
def cancel_job(job_id):
    job = running_jobs.get(job_id)

    if job is None:
        return jsonify({"error": "Job not found"}), 404

    if job["status"] in ["completed", "failed", "cancelled"]:
        return jsonify(job)

    job["cancel_requested"] = True
    job["status"] = "cancelling"
    job["message"] = "Cancelling job"

    return jsonify(job)


@app.route("/job-status/<job_id>", methods=["GET"])
def get_job_status(job_id):
    job = running_jobs.get(job_id)

    if job is None:
        return jsonify({"error": "Job not found"}), 404

    return jsonify(job)


if __name__ == "__main__":
    app.run(debug=True)
    