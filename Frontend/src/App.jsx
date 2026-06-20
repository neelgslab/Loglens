import { useEffect, useRef, useState } from "react";
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";
import "./App.css";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

function App() {
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [sourceName, setSourceName] = useState("Demo Log");
  const [jobId, setJobId] = useState("");
  const [jobStatus, setJobStatus] = useState("");
  const [jobMessage, setJobMessage] = useState("");
  const [jobProgress, setJobProgress] = useState(0);
  const [topProgress, setTopProgress] = useState(0);
  const [activeSection, setActiveSection] = useState("metrics");
  const [eventFilter, setEventFilter] = useState("attacked");

  const uploadRequestRef = useRef(null);

  function wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function safeFileName(name) {
    return name.replace(/[^a-z0-9]/gi, "_").toLowerCase();
  }

  function saveFile(content, fileName, fileType) {
    const blob = new Blob([content], { type: fileType });
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    link.click();

    URL.revokeObjectURL(url);
  }

  function exportJson() {
    if (!report) {
      alert("No report available.");
      return;
    }

    const name = safeFileName(sourceName || "loglens_report");
    const content = JSON.stringify(report, null, 2);

    saveFile(content, `${name}_report.json`, "application/json");
  }

  function cleanCsvValue(value) {
    const text = String(value ?? "");
    return `"${text.replace(/"/g, '""')}"`;
  }

  function exportCsv() {
    if (!report) {
      alert("No report available.");
      return;
    }

    const headers = [
      "timestamp",
      "ip",
      "city",
      "country",
      "method",
      "path",
      "status",
      "http_version",
      "bytes",
      "attack_type",
      "severity",
      "user_agent",
    ];

    const rows = report.events.map((event) => {
      return [
        event.timestamp,
        event.ip,
        event.city,
        event.country,
        event.method,
        event.path,
        event.status,
        event.http_version,
        event.bytes,
        event.attack_type,
        event.severity,
        event.user_agent,
      ]
        .map(cleanCsvValue)
        .join(",");
    });

    const name = safeFileName(sourceName || "loglens_report");
    const csv = [headers.join(","), ...rows].join("\n");

    saveFile(csv, `${name}_events.csv`, "text/csv");
  }

  function uploadWithProgress(formData) {
    return new Promise((resolve, reject) => {
      const request = new XMLHttpRequest();

      uploadRequestRef.current = request;

      request.open("POST", `${API_BASE_URL}/upload-async`);

      request.upload.onprogress = function (event) {
        if (event.lengthComputable) {
          const percent = Math.round((event.loaded / event.total) * 45);

          setTopProgress(percent);
          setJobProgress(percent);
          setJobStatus("uploading");
          setJobMessage(`Uploading file: ${percent}%`);
        }
      };

      request.onload = function () {
        uploadRequestRef.current = null;

        if (request.status >= 200 && request.status < 300) {
          setTopProgress(50);
          setJobProgress(50);
          resolve(JSON.parse(request.responseText));
        } else {
          reject(new Error("Upload failed"));
        }
      };

      request.onerror = function () {
        uploadRequestRef.current = null;
        reject(new Error("Upload failed"));
      };

      request.onabort = function () {
        uploadRequestRef.current = null;
        reject(new Error("Upload cancelled"));
      };

      request.send(formData);
    });
  }

  async function checkJobUntilDone(currentJobId) {
    while (true) {
      const response = await fetch(
        `${API_BASE_URL}/job-status/${currentJobId}`
      );

      if (!response.ok) {
        throw new Error("Could not fetch job status");
      }

      const data = await response.json();
      const backendProgress = data.progress || 0;
      const shownProgress = Math.min(
        99,
        Math.max(50, Math.round(50 + backendProgress * 0.5))
      );

      setJobStatus(data.status);
      setJobMessage(data.message || "");
      setJobProgress(backendProgress);
      setTopProgress(shownProgress);

      if (data.status === "completed") {
        setTopProgress(100);
        setReport(data.report);
        await wait(400);
        setLoading(false);
        return;
      }

      if (data.status === "cancelled") {
        setTopProgress(0);
        setJobProgress(0);
        setJobMessage("Job cancelled");
        setLoading(false);
        return;
      }

      if (data.status === "failed") {
        throw new Error(data.error || "Analysis failed");
      }

      await wait(1000);
    }
  }

  async function cancelCurrentJob() {
    try {
      if (uploadRequestRef.current) {
        uploadRequestRef.current.abort();
        return;
      }

      if (!jobId) {
        setLoading(false);
        setJobStatus("cancelled");
        setJobMessage("Job cancelled");
        setTopProgress(0);
        return;
      }

      setJobStatus("cancelling");
      setJobMessage("Cancelling job");

      const response = await fetch(`${API_BASE_URL}/cancel-job/${jobId}`, {
        method: "POST",
      });

      if (!response.ok) {
        throw new Error("Could not cancel job");
      }
    } catch (err) {
      console.error(err);
      alert("Could not cancel this job.");
    }
  }

  async function loadDemoLog() {
    try {
      setLoading(true);
      setError("");
      setSourceName("Demo Log");
      setJobId("");
      setJobStatus("queued");
      setJobProgress(0);
      setTopProgress(10);
      setJobMessage("Starting demo analysis");
      setEventFilter("attacked");

      const response = await fetch(`${API_BASE_URL}/start-sample-job`, {
        method: "POST",
      });

      if (!response.ok) {
        throw new Error("Could not start demo job");
      }

      const data = await response.json();

      setJobId(data.job_id);
      setJobStatus(data.status);
      setJobMessage(data.message);
      setTopProgress(30);

      await checkJobUntilDone(data.job_id);
    } catch (err) {
      console.error(err);
      setError("Could not connect to the Flask backend.");
      setLoading(false);
      setTopProgress(0);
    }
  }

  function chooseFile(event) {
    const file = event.target.files[0];

    if (file) {
      setSelectedFile(file);
    }
  }

  async function uploadLog() {
    if (!selectedFile) {
      alert("Please choose a .log or .txt file first.");
      return;
    }

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

      setLoading(true);
      setError("");
      setSourceName(selectedFile.name);
      setJobId("");
      setJobStatus("uploading");
      setJobProgress(0);
      setTopProgress(1);
      setJobMessage("Uploading file");
      setEventFilter("attacked");

      const data = await uploadWithProgress(formData);

      setJobId(data.job_id);
      setJobStatus(data.status);
      setJobMessage(data.message);
      setTopProgress(50);

      await checkJobUntilDone(data.job_id);
    } catch (err) {
      console.error(err);

      if (err.message === "Upload cancelled") {
        setLoading(false);
        setJobStatus("cancelled");
        setJobMessage("Upload cancelled");
        setJobProgress(0);
        setTopProgress(0);
        return;
      }

      setError("Upload failed. Make sure the backend is running and the file is valid.");
      setLoading(false);
      setTopProgress(0);
    }
  }

  function markerPosition(place) {
    const longitude = Number(place.longitude);
    const latitude = Number(place.latitude);

    return {
      left: `${((longitude + 180) / 360) * 100}%`,
      top: `${((90 - latitude) / 180) * 100}%`,
    };
  }

  useEffect(() => {
    loadDemoLog();
  }, []);

  if (error) {
    return (
      <div className="page">
        <div className={`topBar ${loading ? "show" : ""}`}>
          <div style={{ width: `${topProgress}%` }}></div>
        </div>

        <header className="hero">
          <h1>LogLens Security Dashboard</h1>
          <p>Attack detection from server logs</p>
        </header>

        <section className="panel">
          <h2>Backend Error</h2>
          <p className="centerText">{error}</p>
          <div className="centerActions">
            <button className="mainBtn" onClick={loadDemoLog}>
              Try Again
            </button>
          </div>
        </section>
      </div>
    );
  }

  if (!loading && report === null && jobStatus === "cancelled") {
    return (
      <div className="page">
        <header className="hero">
          <h1>LogLens Security Dashboard</h1>
          <p>Attack detection from server logs</p>
        </header>

        <section className="panel">
          <h2>Job Cancelled</h2>
          <p className="centerText">{jobMessage}</p>
          <div className="centerActions">
            <button className="mainBtn" onClick={loadDemoLog}>
              Load Demo Log
            </button>
          </div>
        </section>
      </div>
    );
  }

  if (loading && report === null) {
    return (
      <div className="page">
        <div className="topBar show">
          <div style={{ width: `${topProgress}%` }}></div>
        </div>

        <header className="hero">
          <h1>LogLens Security Dashboard</h1>
          <p>Attack detection from server logs</p>
        </header>

        <section className="panel">
          <h2>Processing Log File</h2>

          <p className="centerText">{jobMessage}</p>

          {jobId && <p className="smallCenter">Job ID: {jobId}</p>}

          <div className="progressBox">
            <div style={{ width: `${topProgress}%` }}></div>
          </div>

          <p className="centerText">
            Status: {jobStatus || "starting"} | Progress: {topProgress}%
          </p>

          <div className="centerActions">
            <button className="cancelBtn" onClick={cancelCurrentJob}>
              Cancel Job
            </button>
          </div>
        </section>
      </div>
    );
  }

  if (report === null) {
    return <h2 className="loading">Loading LogLens dashboard...</h2>;
  }

  const attackChartData = Object.entries(report.attack_summary || {}).map(
    ([attackType, count]) => ({
      attackType,
      count,
    })
  );

  const attackerChartData = Object.entries(report.top_attackers || {})
    .map(([ip, count]) => ({
      ip,
      count,
    }))
    .sort((a, b) => b.count - a.count);

  const severityChartData = Object.entries(report.severity_summary || {}).map(
    ([severity, count]) => ({
      severity,
      count,
    })
  );

  const timelineData = report.attacks_per_hour || [];
  const geoLocations = report.geo_locations || [];

  const normalEvents = report.events.filter(
    (event) => event.attack_type === "NORMAL"
  );

  const attackedEvents = report.events.filter(
    (event) => event.attack_type !== "NORMAL"
  );

  const filteredEvents =
    eventFilter === "normal" ? normalEvents : attackedEvents;

  const attackerTableData = attackerChartData.map((attacker, index) => {
    const location = geoLocations.find((place) => place.ip === attacker.ip);

    return {
      rank: index + 1,
      ip: attacker.ip,
      count: attacker.count,
      city: location ? location.city : "Unknown",
      country: location ? location.country : "Unknown",
    };
  });

  const totalAttacks =
    report.total_attacks ??
    report.events.filter((event) => event.attack_type !== "NORMAL").length;

  const topAttacker =
    attackerChartData.length > 0 ? attackerChartData[0].ip : "N/A";

  return (
    <div className="page">
      <div className={`topBar ${loading ? "show" : ""}`}>
        <div style={{ width: `${topProgress}%` }}></div>
      </div>

      <header className="hero">
        <h1>LogLens Security Dashboard</h1>
        <p>Attack detection from server logs</p>
      </header>

      <section className="uploadCard">
        <div className="uploadText">
          <h2>Analyze Log File</h2>
          <p>Current source: {sourceName}</p>

          {jobId && (
            <p className="miniText">
              Job: {jobId.slice(0, 8)}... | {jobStatus} | {topProgress}%
            </p>
          )}

          {report.geoip_status && (
            <p className="miniText">GeoIP: {report.geoip_status}</p>
          )}

          {report.events_limited && (
            <p className="miniText">
              Showing {report.displayed_events} rows out of {report.total_logs}
            </p>
          )}
        </div>

        <div className="uploadActions">
          <label className="fileBtn">
            Choose File
            <input type="file" accept=".log,.txt" onChange={chooseFile} />
          </label>

          <span className="filePill">
            {selectedFile ? selectedFile.name : "No file chosen"}
          </span>

          <button className="mainBtn" onClick={uploadLog} disabled={loading}>
            {loading ? "Processing..." : "Upload and Analyze"}
          </button>

          {loading && (
            <button className="cancelBtn" onClick={cancelCurrentJob}>
              Cancel Job
            </button>
          )}

          <button className="darkBtn" onClick={loadDemoLog} disabled={loading}>
            Load Demo Log
          </button>

          <button className="lightBtn" onClick={exportJson} disabled={loading}>
            Export JSON
          </button>

          <button className="lightBtn" onClick={exportCsv} disabled={loading}>
            Export CSV
          </button>
        </div>
      </section>

      {loading && (
        <section className="panel">
          <h2>Processing Job</h2>
          <p className="centerText">{jobMessage}</p>

          <div className="progressBox">
            <div style={{ width: `${topProgress}%` }}></div>
          </div>

          <p className="centerText">
            Status: {jobStatus} | Progress: {topProgress}%
          </p>

          <div className="centerActions">
            <button className="cancelBtn" onClick={cancelCurrentJob}>
              Cancel Job
            </button>
          </div>
        </section>
      )}

      <section className="dashboardTabs">
        <button
          className={`dashboardTab ${activeSection === "metrics" ? "active" : ""}`}
          onClick={() => setActiveSection("metrics")}
        >
          <span>Attack Metrics</span>
          <strong>{totalAttacks}</strong>
          <p>Charts, severity, timeline and top attackers</p>
        </button>

        <button
          className={`dashboardTab ${activeSection === "geo" ? "active" : ""}`}
          onClick={() => setActiveSection("geo")}
        >
          <span>Geo Info</span>
          <strong>{geoLocations.length}</strong>
          <p>Attacker IP locations and map view</p>
        </button>

        <button
          className={`dashboardTab ${activeSection === "events" ? "active" : ""}`}
          onClick={() => setActiveSection("events")}
        >
          <span>Detected Events</span>
          <strong>{report.displayed_events}</strong>
          <p>Parsed log rows with attack tags</p>
        </button>
      </section>

      {activeSection === "metrics" && (
        <>
          <section className="cards">
            <div className="statCard">
              <span>Total Logs</span>
              <strong>{report.total_logs}</strong>
            </div>

            <div className="statCard">
              <span>Total Attacks</span>
              <strong>{totalAttacks}</strong>
            </div>

            <div className="statCard wideStat">
              <span>Top Attacker</span>
              <strong>{topAttacker}</strong>
            </div>
          </section>

          <section className="panel">
            <h2>Attacks per Hour</h2>

            <ResponsiveContainer width="100%" height={340}>
              <LineChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0c39d" />
                <XAxis dataKey="hour" tick={{ fill: "#132f46", fontSize: 12 }} />
                <YAxis tick={{ fill: "#132f46" }} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="count"
                  stroke="#0f3d5e"
                  strokeWidth={4}
                  dot={{ r: 6, fill: "#e85d04" }}
                  activeDot={{ r: 8 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </section>

          <section className="panel">
            <h2>Attack Summary</h2>

            <ResponsiveContainer width="100%" height={340}>
              <BarChart data={attackChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0c39d" />
                <XAxis
                  dataKey="attackType"
                  tick={{ fill: "#132f46", fontSize: 12 }}
                />
                <YAxis tick={{ fill: "#132f46" }} />
                <Tooltip />
                <Bar dataKey="count" fill="#e85d04" radius={[12, 12, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </section>

          <section className="panel">
            <h2>Severity Summary</h2>

            <ResponsiveContainer width="100%" height={320}>
              <BarChart data={severityChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0c39d" />
                <XAxis
                  dataKey="severity"
                  tick={{ fill: "#132f46", fontSize: 12 }}
                />
                <YAxis tick={{ fill: "#132f46" }} />
                <Tooltip />
                <Bar dataKey="count" fill="#b94700" radius={[12, 12, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </section>

          <section className="panel">
            <h2>Top Attackers</h2>

            <ResponsiveContainer width="100%" height={340}>
              <BarChart data={attackerChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0c39d" />
                <XAxis dataKey="ip" tick={{ fill: "#132f46", fontSize: 12 }} />
                <YAxis tick={{ fill: "#132f46" }} />
                <Tooltip />
                <Bar dataKey="count" fill="#0f3d5e" radius={[12, 12, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </section>

          <section className="panel">
            <h2>Top Attackers Table</h2>

            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>IP Address</th>
                    <th>Attack Count</th>
                    <th>City</th>
                    <th>Country</th>
                  </tr>
                </thead>

                <tbody>
                  {attackerTableData.map((attacker) => (
                    <tr key={attacker.ip}>
                      <td>{attacker.rank}</td>
                      <td>{attacker.ip}</td>
                      <td>{attacker.count}</td>
                      <td>{attacker.city}</td>
                      <td>{attacker.country}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {activeSection === "geo" && (
        <>
          <section className="panel">
            <h2>Geo Attack Map</h2>

            <div className="mapBox">
              <div className="mapLines"></div>

              {geoLocations.map((place, index) => (
                <div
                  className="mapPin"
                  style={markerPosition(place)}
                  key={`${place.ip}-${index}`}
                  title={`${place.city}, ${place.country} - ${place.count} attacks`}
                >
                  <span className="pinPulse"></span>
                  <span className="pinDot"></span>
                  <span className="pinLabel">
                    {place.city}
                    <strong>{place.count}</strong>
                  </span>
                </div>
              ))}
            </div>

            <div className="geoGrid">
              {geoLocations.map((place, index) => (
                <div className="geoItem" key={`${place.ip}-card-${index}`}>
                  <span>{place.ip}</span>
                  <strong>
                    {place.city}, {place.country}
                  </strong>
                  <p>{place.count} attacks detected</p>
                </div>
              ))}
            </div>
          </section>

          <section className="panel">
            <h2>Geo Info Table</h2>

            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>City</th>
                    <th>Country</th>
                    <th>Latitude</th>
                    <th>Longitude</th>
                    <th>Attack Count</th>
                  </tr>
                </thead>

                <tbody>
                  {geoLocations.map((place, index) => (
                    <tr key={`${place.ip}-geo-${index}`}>
                      <td>{place.ip}</td>
                      <td>{place.city}</td>
                      <td>{place.country}</td>
                      <td>{place.latitude}</td>
                      <td>{place.longitude}</td>
                      <td>{place.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {activeSection === "events" && (
        <section className="panel">
          <h2>Detected Events</h2>

          <div className="eventFilterBox">
            <button
              className={`eventFilterBtn ${eventFilter === "attacked" ? "active" : ""}`}
              onClick={() => setEventFilter("attacked")}
            >
              Attacked Events
              <strong>{attackedEvents.length}</strong>
            </button>

            <button
              className={`eventFilterBtn ${eventFilter === "normal" ? "active" : ""}`}
              onClick={() => setEventFilter("normal")}
            >
              Normal Events
              <strong>{normalEvents.length}</strong>
            </button>
          </div>

          <p className="eventFilterNote">
            Showing {filteredEvents.length}{" "}
            {eventFilter === "normal" ? "normal" : "attacked"} events
          </p>

          <div className="tableWrap eventTableWrap">
            <table className="eventsTable">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>IP</th>
                  <th>Location</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Status</th>
                  <th>HTTP</th>
                  <th>Bytes</th>
                  <th>Attack Type</th>
                  <th>Severity</th>
                  <th>User Agent</th>
                </tr>
              </thead>

              <tbody>
                {filteredEvents.map((event, index) => (
                  <tr key={`${event.timestamp}-${event.ip}-${index}`}>
                    <td>{event.timestamp}</td>
                    <td>{event.ip}</td>
                    <td>
                      {event.city}, {event.country}
                    </td>
                    <td>{event.method}</td>
                    <td className="pathCell">{event.path}</td>
                    <td>{event.status}</td>
                    <td>{event.http_version}</td>
                    <td>{event.bytes}</td>
                    <td>
                      <span className={`badge ${event.attack_type}`}>
                        {event.attack_type}
                      </span>
                    </td>
                    <td>
                      <span className={`risk ${event.severity}`}>
                        {event.severity}
                      </span>
                    </td>
                    <td className="agentCell">{event.user_agent}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

export default App;
