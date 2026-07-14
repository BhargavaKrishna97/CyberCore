import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from "chart.js";

import { Bar } from "react-chartjs-2";

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend
);

function AlertBarChart({ counts }) {
  const data = {
    labels: ["Critical", "High", "Medium", "Info"],
    datasets: [
      {
        label: "Alert Count",
        data: [
          counts.critical,
          counts.high,
          counts.medium,
          counts.info,
        ],
        backgroundColor: [
          "#dc3545",
          "#ffc107",
          "#0d6efd",
          "#198754",
        ],
        borderColor: [
          "#dc3545",
          "#ffc107",
          "#0d6efd",
          "#198754",
        ],
        borderWidth: 1,
      },
    ],
  };

  return (
    <div>
      <Bar data={data} />
    </div>
  );
}

export default AlertBarChart;
