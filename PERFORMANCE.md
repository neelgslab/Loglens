# Performance Note

LogLens is designed to handle larger log files better than a browser-only app.

The browser only handles the dashboard. The backend does the heavy work.

## Line-by-Line Parsing

The parser reads the uploaded file line-by-line.

It does not load the full log file into memory during analysis.

Basic flow:

```text
read one line
parse it
check for attacks
update counters
move to the next line
```

This is safer for large files.

## Async Job Flow

Large files can take time, so LogLens uses a job system.

Flow:

```text
Upload file -> Create job ID -> Process file -> Check progress -> Show report
```

The frontend keeps checking the backend for progress.

Main routes:

```text
POST /upload-async
GET /job-status/<job_id>
POST /cancel-job/<job_id>
```

## Cancel Job

The user can cancel a running job.

When cancelled:

* backend stops processing
* job status changes to cancelled
* uploaded file is removed

This helps when a wrong or very large file is uploaded.

## Frontend Performance

The frontend does not show unlimited rows.

It limits displayed events so the browser stays smooth.

The Detected Events section also has:

* normal event filter
* attacked event filter
* vertical scrolling
* horizontal scrolling

This makes the table easier to use.

## Upload Handling

In this version, Flask saves the uploaded file first.

Then the parser reads the saved file line-by-line from disk.

So it is not real-time upload streaming, but the analysis step is still memory-safe.

## Ignored Files

Large and generated files are ignored from GitHub:

```text
Backend/uploads/
Backend/job_results/
Backend/results.json
Backend/*.log
Backend/GeoLite2-City.mmdb
Frontend/node_modules/
Frontend/dist/
```

## Summary

Main performance choices:

* backend parsing
* line-by-line reading
* async job ID system
* progress polling
* cancel job option
* limited event rows
* frontend filters
* scrollable event table

These choices keep LogLens simple, usable, and safer for larger log files.
