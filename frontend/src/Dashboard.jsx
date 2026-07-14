import { useEffect, useState } from "react";
import axios from "axios";
import AlertPieChart from "./AlertPieChart";
import AlertBarChart from "./AlertBarChart";
import AlertTrendChart from "./AlertTrendChart";
import VirusTotalLookup from "./VirusTotalLookup";
import { CSVLink } from "react-csv";


function Dashboard() {
  const [dashboard, setDashboard] = useState(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [showModal, setShowModal] = useState(false);


  useEffect(() => {
    const fetchData = () => {
      axios
        .get("http://127.0.0.1:5000/api/monitor/dashboard")
        .then((res) => {
          setDashboard(res.data);
        })
        .catch((err) => {
          console.error(err);
        });
    };
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  if (!dashboard) {
    return (
      <div className="container mt-5">
        <h2>Loading Dashboard...</h2>
      </div>
    );
  }
  const filteredAlerts = dashboard.alerts.filter((alert) => {
    const matchesSearch = 
      alert.message.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = 
      severityFilter === "all" ||
      alert.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const csvData = filteredAlerts.map((alert) => ({
    ID: alert.id,
    Severity: alert.severity,
    Message: alert.message,
    Type: alert.alert_type || "N/A",
    File: alert.file_path || "N/A",
    Created: alert.created_at || "N/A",
  }));

  return (
    <div className="container mt-4">
      <h1 className="text-center mb-4">
        CyberCore SOC Dashboard
      </h1>
      <div className="text-end mb-3">
        <button
          className="btn btn-outline-danger"
          onClick={async () => {
            if (!window.confirm("Reset Dashboard?")) return;
            await axios.post(
              "http://127.0.0.1:5000/api/monitor/reset"
            );
            window.location.reload();
          }}
        >
          Reset Dashboard
        </button>
      </div>
      <p className="text-center text-muted mb-4">
      Real-Time Malware Detection & Threat Monitoring
      </p>

      <div className="row">

        <div className="col-md-3">
          <div className="card text-white bg-danger mb-3">
            <div className="card-body">
              <h5>Critical</h5>
              <h2>{dashboard.counts.critical}</h2>
            </div>
          </div>
        </div>

        <div className="col-md-3">
          <div className="card text-white bg-warning mb-3">
            <div className="card-body">
              <h5>High</h5>
              <h2>{dashboard.counts.high}</h2>
            </div>
          </div>
        </div>

        <div className="col-md-3">
          <div className="card text-white bg-primary mb-3">
            <div className="card-body">
              <h5>Medium</h5>
              <h2>{dashboard.counts.medium}</h2>
            </div>
          </div>
        </div>

        <div className="col-md-3">
          <div className="card text-white bg-success mb-3">
            <div className="card-body">
              <h5>Info</h5>
              <h2>{dashboard.counts.info}</h2>
            </div>
          </div>
        </div>
             
        <div className="col-md-3">
          <div className="card text-white bg-dark mb-3">
            <div className="card-body">
              <h5>Threats</h5>
              <h2>{dashboard.threat_count}</h2>
            </div>
          </div>
        </div>
      </div>
      <div className="card mb-4">
        <div className="card-header">
          Alert Distribution
        </div>
        <div className="card-body d-flex justify-content-center">
          <AlertPieChart counts={dashboard.counts} />
        </div>
      </div>
      <div className="card mb-4">
        <div className="card-header">
          Alert Counts Bar Chart
        </div>
        <div className="card-body">
          <AlertBarChart counts={dashboard.counts} />
        </div>
      </div>
      <div className="card mb-4">
        <div className="card-header">
          Alert Trend (Last 5 Hours)
        </div>
        
        <div className="card-body">
          <AlertTrendChart/>
        </div>
      </div>
      <VirusTotalLookup />
      <div className="card mb-4">
        <div className="card-header">
          Recent Threats
        </div>
        <div className="card-body">
          <div className="table-responsive">
           <table className="table table-striped table-bordered table-hover">
             <thead>
               <tr>
                 <th>ID</th>
                 <th>Type</th>
                 <th>Severity</th>
                 <th>Source</th>
                 <th>Description</th>
               </tr>
             </thead>
             <tbody>
               {dashboard.threats.map((threat) => (
                 <tr key={threat.id}>
                   <td>{threat.id}</td>
                   <td>{threat.threat_type}</td>
                   <td>
                     <span
                       className={`badge ${
                         threat.severity === "critical"
                           ? "bg-danger"
                           : threat.severity === "high"
                           ? "bg-warning"
                           : "bg-primary"
                       }`}
                     >
                       {threat.severity}
                     </span>
                   </td>
                   <td>{threat.source}</td>
                   <td style={{ 
                         maxWidth: "350px", 
                         whiteSpace: "normal", 
                         wordBreak: "break-word",
                       }}>
                     {threat.description}
                   </td>
                 </tr>
               ))}
             </tbody>
           </table>
         </div>
        </div>
      </div>
      <div className="card mb-4">
        <div className="card-header">
          Quarantined Files
        </div>

        <div className="card-body">
          <ul className="list-group">
            {dashboard.quarantine.files.map((file, index) => (
              <li className="list-group-item" key={index}>🦠{file}</li>
            ))}
          </ul>
        </div>
      </div>
      <div className="mb-3">
        <input
          type="text"
          className="form-control shadow-sm"
          placeholder="Search alerts by message..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      <div className="mb-3">
        <button
          className="btn btn-secondary me-2"
          onClick={() => setSeverityFilter("all")}
        >
        All
        </button>
        <button
          className="btn btn-danger me-2"
          onClick={() => setSeverityFilter("critical")}
        >
         Critical
        </button>
        <button
          className="btn btn-warning me-2"
          onClick={() => setSeverityFilter("high")}
        >
          High
        </button>
        <button
          className="btn btn-primary me-2"
          onClick={() => setSeverityFilter("medium")}
        >
         Medium
        </button>
        <button
          className="btn btn-success"
           onClick={() => setSeverityFilter("info")}
        >
          Info
        </button>
      </div>
      <div className="mb-3">
        <CSVLink
          data={csvData}
          filename={"alerts.csv"}
          className="btn btn-dark"
        >
          Export Alerts CSV
        </CSVLink>
      </div>

      <div className="card">

        <div className="card-header">
          Recent Alerts
        </div>

        <div className="card-body">

          <table className="table table-striped table-hover">

            <thead>
              <tr>
                <th>ID</th>
                <th>Severity</th>
                <th>Message</th>
                <th>Timestamp</th>
              </tr>
            </thead>

            <tbody>
              {filteredAlerts.map((alert) => (
                <tr 
                  key={alert.id}
                  style={{ cursor: "pointer" }}
                  onClick={() => {
                    setSelectedAlert(alert);
                    setShowModal(true);
                  }}
                >
                  <td>{alert.id}</td>
                  <td>
                    <span
                      className={`badge ${
                        alert.severity === "critical"
                          ? "bg-danger"
                          : alert.severity === "high"
                          ? "bg-warning"
                          : alert.severity === "medium"
                          ? "bg-primary"
                          : "bg-success"
                      }`}
                     >
                      {alert.severity}
                     </span>
                  </td>
                  <td>{alert.message}</td>
                  <td>{alert.created_at || "N/A"}</td>
                </tr>
              ))}
            </tbody>

          </table>

        </div>

      </div>
      {showModal && selectedAlert && (
        <div
          className="modal d-block"
          tabIndex="-1"
          style={{ backgroundColor: "rgba(0,0,0,0.5)" }}
        >
          <div className="modal-dialog">
            <div className="modal-content">
              <div className = "modal-header">
                <h5 className="modal-title">
                  Alert Details
                </h5>
                <button
                  className="btn-close"
                  onClick={() => setShowModal(false)}
                ></button>
              </div>
              <div className="modal-body">
                <p>
                  <strong>ID:</strong> {selectedAlert.id}
                </p>
                <p>
                  <strong>Severity:</strong> {selectedAlert.severity}
                </p>
                <p>
                  <strong>Message:</strong> {selectedAlert.message}
                </p>
                <p>
                  <strong>Type:</strong> {selectedAlert.alert_type || "N/A"} 
                </p>
                <p>
                  <strong>File:</strong> {selectedAlert.file_path || "N/A"}
                </p>
                <p>
                  <strong>Created:</strong> {selectedAlert.created_at || "N/A"}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
