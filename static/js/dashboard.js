// WebSocket connection
const socket = io();

// Chart instances
let protocolChart;
let appChart;
let ppsChart;

// PPS history for time series
const ppsHistory = [];
const ppsLabels = [];
const maxPpsPoints = 60;

// Initialize charts
function initCharts() {
  // Protocol Distribution Chart
  const protocolCtx = document.getElementById("protocol-chart").getContext("2d");
  protocolChart = new Chart(protocolCtx, {
    type: "doughnut",
    data: {
      labels: ["TCP", "UDP", "ICMP", "ARP", "IPv6", "Other"],
      datasets: [
        {
          data: [0, 0, 0, 0, 0, 0],
          backgroundColor: [
            "rgba(59, 130, 246, 0.8)",
            "rgba(16, 185, 129, 0.8)",
            "rgba(245, 158, 11, 0.8)",
            "rgba(139, 92, 246, 0.8)",
            "rgba(236, 72, 153, 0.8)",
            "rgba(107, 114, 128, 0.8)",
          ],
          borderWidth: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            padding: 15,
            usePointStyle: true,
          },
        },
      },
    },
  });

  // Application Protocol Chart
  const appCtx = document.getElementById("app-chart").getContext("2d");
  appChart = new Chart(appCtx, {
    type: "doughnut",
    data: {
      labels: ["HTTP", "HTTPS", "SSH", "DNS", "SMTP", "Other"],
      datasets: [
        {
          data: [0, 0, 0, 0, 0, 0],
          backgroundColor: [
            "rgba(239, 68, 68, 0.8)",
            "rgba(34, 197, 94, 0.8)",
            "rgba(168, 85, 247, 0.8)",
            "rgba(14, 165, 233, 0.8)",
            "rgba(249, 115, 22, 0.8)",
            "rgba(107, 114, 128, 0.8)",
          ],
          borderWidth: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            padding: 15,
            usePointStyle: true,
          },
        },
      },
    },
  });

  // Packets Per Second Chart
  const ppsCtx = document.getElementById("pps-chart").getContext("2d");
  ppsChart = new Chart(ppsCtx, {
    type: "line",
    data: {
      labels: ppsLabels,
      datasets: [
        {
          label: "Packets/sec",
          data: ppsHistory,
          borderColor: "rgba(59, 130, 246, 1)",
          backgroundColor: "rgba(59, 130, 246, 0.1)",
          fill: true,
          tension: 0.4,
          pointRadius: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      scales: {
        y: {
          beginAtZero: true,
          grid: {
            color: "rgba(0, 0, 0, 0.05)",
          },
        },
        x: {
          grid: {
            display: false,
          },
          ticks: {
            maxTicksLimit: 10,
          },
        },
      },
      plugins: {
        legend: {
          display: false,
        },
      },
    },
  });
}

// Update stats display
function updateStats(stats) {
  document.getElementById("total-packets").textContent =
    stats.total.toLocaleString();
  document.getElementById("pps").textContent = stats.packets_per_second;
  document.getElementById("tcp-count").textContent =
    stats.counters.ip.tcp.toLocaleString();
  document.getElementById("udp-count").textContent =
    stats.counters.ip.udp.toLocaleString();
  document.getElementById("arp-count").textContent =
    stats.counters.ethernet.arp.toLocaleString();
  document.getElementById("ipv6-count").textContent =
    stats.counters.ip_version.ipv6.toLocaleString();

  // Update protocol chart
  protocolChart.data.datasets[0].data = [
    stats.counters.ip.tcp,
    stats.counters.ip.udp,
    stats.counters.ip.icmp,
    stats.counters.ethernet.arp,
    stats.counters.ip_version.ipv6,
    stats.counters.ip.others + stats.counters.ethernet.others,
  ];
  protocolChart.update("none");

  // Update application chart
  appChart.data.datasets[0].data = [
    stats.counters.application.http,
    stats.counters.application.https,
    stats.counters.application.ssh,
    stats.counters.application.dns,
    stats.counters.application.smtp,
    stats.counters.application.others,
  ];
  appChart.update("none");

  // Update PPS chart
  const now = new Date().toLocaleTimeString();
  ppsLabels.push(now);
  ppsHistory.push(stats.packets_per_second);

  if (ppsLabels.length > maxPpsPoints) {
    ppsLabels.shift();
    ppsHistory.shift();
  }

  ppsChart.update("none");
}

// Get badge class for protocol
function getBadgeClass(type, transport) {
  if (transport === "TCP") return "badge-tcp";
  if (transport === "UDP") return "badge-udp";
  if (transport === "ICMP") return "badge-icmp";
  if (type === "ARP") return "badge-arp";
  if (type === "IPv6") return "badge-ipv6";
  return "badge-other";
}

// Add packet to table
function addPacketToTable(packet) {
  const tbody = document.getElementById("packet-tbody");
  const row = document.createElement("tr");

  const badgeClass = getBadgeClass(packet.type, packet.transport);
  const protocol = packet.transport || packet.type;
  const port = packet.dst_port ? `${packet.src_port} → ${packet.dst_port}` : "-";

  row.innerHTML = `
    <td>${packet.timestamp}</td>
    <td><span class="badge ${badgeClass}">${packet.type}</span></td>
    <td>${packet.src_ip || "-"}</td>
    <td>${packet.dst_ip || "-"}</td>
    <td>${packet.application || protocol}</td>
    <td>${port}</td>
    <td>${packet.size} B</td>
  `;

  // Insert at beginning
  tbody.insertBefore(row, tbody.firstChild);

  // Keep only 200 rows
  while (tbody.children.length > 200) {
    tbody.removeChild(tbody.lastChild);
  }

  // Update count
  document.getElementById("packet-count").textContent =
    `(${tbody.children.length}/200)`;
}

// Load packet history
function loadHistory(packets) {
  const tbody = document.getElementById("packet-tbody");
  tbody.innerHTML = "";

  packets.reverse().forEach((packet) => {
    addPacketToTable(packet);
  });
}

// Socket event handlers
socket.on("connect", () => {
  console.log("Connected to server");
});

socket.on("disconnect", () => {
  console.log("Disconnected from server");
});

socket.on("stats_update", (stats) => {
  updateStats(stats);
});

socket.on("new_packet", (packet) => {
  addPacketToTable(packet);
});

socket.on("history", (packets) => {
  loadHistory(packets);
});

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  initCharts();
});