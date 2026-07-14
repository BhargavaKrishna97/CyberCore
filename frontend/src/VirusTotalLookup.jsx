import { useState } from "react";
import axios from "axios";

function VirusTotalLookup() {
  const [hash, setHash] = useState("");
  const [result, setResult] = useState(null);
  const [file, setFile] = useState(null);

  const checkHash = async () => {
    console.log("HASH VALUE:", hash);
    try {
      const res = await axios.post(
        "http://127.0.0.1:5000/api/virustotal/check-hash",
        {
          sha256: hash,
        }
      );
      console.log("RESPONSE:", res.data);

      setResult(res.data);
    } catch (err) {
      console.error("ERROR:",err);
      if (err.response) {
       console.log("BACKEND ERROR:", err.response.data);
      }
      alert("Lookup failed");
    }
  };
  

  const uploadFile = async () => {
    if (!file) {
      alert("Select a file first");
      return;
    }
  const formData = new FormData();
  formData.append("file", file);
  try{
    const res = await axios.post(
      "http://127.0.0.1:5000/api/virustotal/upload",
      formData,
      {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      }
    );
    console.log("UPLOAD RESPONSE:", res.data);
    setResult(res.data);
   }catch(err) {
    console.error(err);
    alert("Upload failed");
   }
  };
  return (
    <div className="card mb-4">
      <div className="card-header">
        VirusTotal Hash Lookup
      </div>

      <div className="card-body">

        <input
          type="text"
          className="form-control mb-3"
          placeholder="Enter SHA256 Hash"
          value={hash}
          onChange={(e) => setHash(e.target.value)}
        />

        <button
          className="btn btn-primary"
          onClick={checkHash}
        >
          Check Hash
        </button>
        
        <hr />
        <h5>Upload File for VirusTotal Scan</h5>
        <input
          type="file"
          className="form-control mb-3"
          onChange={(e) => setFile(e.target.files[0])}
        />
        <button
          className="btn btn-success mb-3"
          onClick={uploadFile}
        >
          Upload & Scan
        </button>

        {result && (
          <div className="mt-3">

            <p>
              <strong>SHA256:</strong>
              {" "}
              {result.sha256}
            </p>

            <p>
              <strong>Malicious:</strong>
              {" "}
              {result.malicious}
            </p>

            <p>
              <strong>Total Engines:</strong>
              {" "}
              {result.total}
            </p>

            <p>
              <strong>Status:</strong>
              {" "}
              {result.status}
            </p>

          </div>
        )}

      </div>
    </div>
  );
}

export default VirusTotalLookup;
