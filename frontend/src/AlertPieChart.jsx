import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";

import { Pie } from "react-chartjs-2";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend
);

function AlertPieChart({ counts }) {

  const data = {
    labels: [
      "Critical",
      "High",
      "Medium",
      "Info",
    ],

    datasets: [
      {
        data: [
          counts.critical,
          counts.high,
          counts.medium,
          counts.info,
        ],
        backgroundColor: [
          "#dc3545", // Critical - Red
          "#ffc107", // High - Yellow
          "#0d6efd", // Medium - Blue
          "#198754", // Info - Green
        ],
        borderWidth: 1,
      },
    ],
  };

  return (
    <div style={{ width: "400px" }}>
      <Pie data={data} />
    </div>
  );
}

export default AlertPieChart;
