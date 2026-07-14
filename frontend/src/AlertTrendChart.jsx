import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
} from "chart.js";

import { Line } from "react-chartjs-2";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

function AlertTrendChart() {
  const data = {
    labels: [
      "1 Hour Ago",
      "2 Hours Ago",
      "3 Hours Ago",
      "4 Hours Ago",
      "5 Hours Ago"
    ],
    datasets: [
      {
        label: "Alerts",
        data: [3, 7, 5, 10, 8],
        borderColor: "red",
        backgroundColor: "red",
        tension: 0.4
      }
    ]
  };

  return <Line data={data} />;
}

export default AlertTrendChart;
