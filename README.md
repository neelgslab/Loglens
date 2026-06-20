## Links

GitHub Repository: https://github.com/neelgslab/Loglens

Live Application: https://loglens-two.vercel.app/

Backend API: https://loglens-r91o.onrender.com

# LogLens

LogLens is a simple security dashboard for web server log files.

It helps upload a `.log` file, scan it for attacks, and show the result using charts, tables, and location data.

## Features

* Upload `.log` and `.txt` files
* Load a demo log
* Parse Apache/Nginx style access logs
* Detect SQL Injection, XSS, Directory Traversal, and Brute Force
* Separate normal events and attacked events
* Show attack charts and top attackers
* Show GeoIP location data
* Export report as JSON
* Export events as CSV
* Use job ID, progress tracking, and cancel job

## Dashboard Sections

### Attack Metrics

Shows total logs, total attacks, top attacker, attacks per hour, attack summary, severity summary, and top attackers.

### Geo Info

Shows attacker IP locations using a simple map view, location cards, and a GeoIP table.

### Detected Events

Shows parsed log rows.

It has two filters:

* Attacked Events
* Normal Events

The table can scroll vertically and horizontally, so the user can view all columns from timestamp to user agent.

## Data Extracted

For each valid log line, LogLens extracts:

* IP address
* timestamp
* method
* path
* status code
* HTTP version
* bytes
* user agent

Each row is also given an attack type and severity.

## Tech Used

Backend:

* Python
* Flask
* Regex
* MaxMind GeoLite2

Frontend:

* React
* Vite
* Recharts
* CSS

## Important Files

Backend:

* `app.py` runs the Flask server
* `parser.py` parses logs line-by-line
* `detector.py` detects attacks
* `geo_lookup.py` adds location data
* `signatures.json` stores attack patterns
* `generate_sample_log.py` creates demo logs

Frontend:

* `App.jsx` contains dashboard logic
* `App.css` contains styling

## Run Backend

Open terminal inside `Backend`.

```bash
py -m pip install -r requirements.txt
py generate_sample_log.py
py app.py
```

Backend runs at:

```text
http://127.0.0.1:5000
```

## Run Frontend

Open terminal inside `Frontend`.

```bash
npm install
npm.cmd run dev
```

Frontend runs at:

```text
http://localhost:5173
```

## GeoIP Setup

Place this file inside the `Backend` folder:

```text
GeoLite2-City.mmdb
```

This file is not pushed to GitHub.

If it is missing, the app still works, but location data may not be available.

## Main Routes

```text
GET  /
GET  /analyze-sample
POST /start-sample-job
POST /upload
POST /upload-async
POST /cancel-job/<job_id>
GET  /job-status/<job_id>
```

## Limitations

This is a prototype, not a full SIEM.

Current limitations:

* attack detection is based on regex patterns
* jobs are stored in memory
* uploaded files are saved first, then parsed
* the map is a simple visual map
* the frontend limits displayed rows for smoother performance

LogLens still covers the main SIEM-lite flow: upload logs, parse logs, detect attacks, and show the result clearly.
