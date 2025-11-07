// Sidebar toggle
const sidebar = document.getElementById("sidebar");
const menuToggle = document.getElementById("menuToggle");
menuToggle.addEventListener("click", () => {
  sidebar.classList.toggle("collapsed");
  menuToggle.classList.toggle("active");
});

// Membership Modal
const membershipModal = document.getElementById("membershipModal");
function openMembershipModal() {
  membershipModal.style.display = "flex";
}
function closeMembershipModal() {
  membershipModal.style.display = "none";
}
// Sidebar Member Approvals click
document
  .getElementById("sidebarMemberApprovals")
  .addEventListener("click", function (e) {
    e.preventDefault();
    openMembershipModal();
  });

function approveStudent(btn) {
  const row = btn.closest("tr");
  const name = row.cells[0].innerText;
  const applyingFor = row.cells[1].innerText;
  const currentClubs = row.cells[2].innerText.replace(/[^0-9]/g, "");

  document.querySelector("#approvedTable tbody").insertAdjacentHTML(
    "beforeend",
    `<tr>
      <td>${name}</td>
      <td>${applyingFor}</td>
      <td>${currentClubs}</td>
      <td><button class="delete-row" onclick="deleteMemberRow(this)"><i class='ri-delete-bin-line'></i> Delete</button></td>
    </tr>`
  );

  row.remove();
  updateCounts();
}

function rejectStudent(btn) {
  const row = btn.closest("tr");
  const name = row.cells[0].innerText;
  const applyingFor = row.cells[1].innerText;
  const currentClubs = row.cells[2].innerText.replace(/[^0-9]/g, "");

  document.querySelector("#rejectedTable tbody").insertAdjacentHTML(
    "beforeend",
    `<tr>
      <td>${name}</td>
      <td>${applyingFor}</td>
      <td>${currentClubs}</td>
      <td><button class="delete-row" onclick="deleteMemberRow(this)"><i class='ri-delete-bin-line'></i> Delete</button></td>
    </tr>`
  );

  row.remove();
  updateCounts();
}

function deleteMemberRow(btn) {
  const row = btn.closest("tr");
  const table = row.closest("table");
  if (confirm("Delete this record?")) {
    // If deleting from approved or rejected, move back to pending
    if (table.id === "approvedTable" || table.id === "rejectedTable") {
      const name = row.cells[0].innerText;
      const applyingFor = row.cells[1].innerText;
      const currentClubs = row.cells[2].innerText;
      document.querySelector("#pendingTable tbody").insertAdjacentHTML(
        "beforeend",
        `<tr data-clubs="${currentClubs}">
                <td>${name}</td>
                <td>${applyingFor}</td>
                <td><span class="badge">${currentClubs}</span></td>
                <td>
                  <button class="approve" onclick="approveStudent(this)"><i class="ri-check-line"></i> Approve</button>
                  <button class="reject" onclick="rejectStudent(this)"><i class="ri-close-line"></i> Reject</button>
                </td>
              </tr>`
      );
    }
    row.remove();
    updateCounts();
  }
}

// Tabs behavior
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document
      .querySelectorAll(".tab-btn")
      .forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const id = btn.getAttribute("data-tab");
    document.querySelectorAll(".tab-pane").forEach((p) => {
      p.style.display = p.id === id ? "" : "none";
    });
  });
});

// Update counts for membership tables and toolbar
function updateCounts() {
  const approved = document.querySelectorAll("#approvedTable tbody tr").length;
  const rejected = document.querySelectorAll("#rejectedTable tbody tr").length;
  const pending = document.querySelectorAll("#pendingTable tbody tr").length;
  const approvedCountEl = document.getElementById("approvedCount");
  const rejectedCountEl = document.getElementById("rejectedCount");
  const approvedTop = document.getElementById("approvedCountTop");
  const rejectedTop = document.getElementById("rejectedCountTop");
  const pendingCountEl = document.getElementById("pendingCount");
  const pendingHeaderEl = document.getElementById("pendingCountHeader");
  if (approvedCountEl) approvedCountEl.innerText = approved;
  if (rejectedCountEl) rejectedCountEl.innerText = rejected;
  if (approvedTop) approvedTop.innerText = approved;
  if (rejectedTop) rejectedTop.innerText = rejected;
  if (pendingCountEl) pendingCountEl.innerText = pending;
  if (pendingHeaderEl) pendingHeaderEl.innerText = pending;
}

// Membership search filter
const memberSearch = document.getElementById("memberSearch");
if (memberSearch) {
  memberSearch.addEventListener("input", () => {
    const q = memberSearch.value.toLowerCase();
    document.querySelectorAll("#pendingTable tbody tr").forEach((tr) => {
      const name = tr.cells[0]?.innerText.toLowerCase() || "";
      const club = tr.cells[1]?.innerText.toLowerCase() || "";
      tr.style.display =
        !q || name.includes(q) || club.includes(q) ? "" : "none";
    });
  });
}

// Attendance Modal
const attendanceModal = document.getElementById("attendanceModal");
function closeAttendanceModal() {
  attendanceModal.style.display = "none";
}

function updateAttendanceCounts() {
  const presentCount = document.querySelectorAll(
    "#attendanceTable .present"
  ).length;
  const absentCount = document.querySelectorAll(
    "#attendanceTable .absent"
  ).length;
  document.getElementById("presentCount").innerText = presentCount;
  document.getElementById("absentCount").innerText = absentCount;
}

function markPresent(btn) {
  const row = btn.closest("tr");
  const statusCell = row.querySelector(".status");
  statusCell.innerText = "Present";
  statusCell.classList.remove("absent");
  statusCell.classList.add("present");
  updateAttendanceCounts();
}

function markAbsent(btn) {
  const row = btn.closest("tr");
  const statusCell = row.querySelector(".status");
  statusCell.innerText = "Absent";
  statusCell.classList.remove("present");
  statusCell.classList.add("absent");
  updateAttendanceCounts();
}

// Attendance search and filter
const attnSearch = document.getElementById("attnSearch");
const attnFilter = document.getElementById("attnFilter");
function applyAttendanceFilters() {
  const q = (attnSearch.value || "").toLowerCase();
  const filter = attnFilter.value; // all | present | absent | not_marked
  document.querySelectorAll("#attendanceTable tbody tr").forEach((tr) => {
    const name = tr.cells[0].innerText.toLowerCase();
    const statusEl = tr.querySelector(".status");
    const statusText = statusEl ? statusEl.innerText.toLowerCase() : "";
    const matchesSearch = !q || name.includes(q);
    const matchesFilter =
      filter === "all" ||
      (filter === "present" && statusText === "present") ||
      (filter === "absent" && statusText === "absent") ||
      (filter === "not_marked" && statusText === "not marked");
    tr.style.display = matchesSearch && matchesFilter ? "" : "none";
  });
}
if (attnSearch && attnFilter) {
  attnSearch.addEventListener("input", applyAttendanceFilters);
  attnFilter.addEventListener("change", applyAttendanceFilters);
}

// Export visible attendance rows to CSV
const attnExportBtn = document.getElementById("attnExport");
function exportAttendanceCSV() {
  const rows = Array.from(
    document.querySelectorAll("#attendanceTable tbody tr")
  ).filter((tr) => getComputedStyle(tr).display !== "none");
  const data = [["Name", "Status"]];
  rows.forEach((tr) => {
    const name = (tr.cells[0]?.innerText || "").trim();
    const status = (tr.querySelector(".status")?.innerText || "").trim();
    data.push([name, status]);
  });
  const csv = data
    .map((r) =>
      r.map((v) => '"' + String(v).replace(/"/g, '""') + '"').join(",")
    )
    .join("\r\n");
  const blob = new Blob(["\uFEFF" + csv], {
    type: "text/csv;charset=utf-8;",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const now = new Date();
  const yyyy = now.getFullYear();
  const mm = String(now.getMonth() + 1).padStart(2, "0");
  const dd = String(now.getDate()).padStart(2, "0");
  a.href = url;
  a.download = `attendance-${yyyy}-${mm}-${dd}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
if (attnExportBtn) {
  attnExportBtn.addEventListener("click", exportAttendanceCSV);
}
const ctx = document.getElementById("analyticsChart").getContext("2d");
let analyticsChart = new Chart(ctx, {
  type: "bar",
  data: {
    labels: ["Jan", "Feb", "Mar", "Apr", "May"],
    datasets: [
      {
        label: "Attendance %",
        data: [90, 85, 80, 95, 88],
        backgroundColor: "#8e0e00",
      },
    ],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: { beginAtZero: true, max: 100 },
    },
  },
});

function refreshChart() {
  analyticsChart.data.datasets[0].data = Array.from(
    { length: 5 },
    () => Math.floor(Math.random() * 21) + 80
  );
  analyticsChart.update();
}

// Create Post Modal
const postModal = document.getElementById("postModal");
const postForm = document.getElementById("postForm");
const postList = document.getElementById("postList");

function createPost() {
  postModal.style.display = "flex";
}

function closePostModal() {
  postModal.style.display = "none";
}

postForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const title = document.getElementById("postTitle").value;
  const message = document.getElementById("postMessage").value;
  const audience = document.getElementById("postAudience").value;

  // Create post item with delete button
  const li = document.createElement("li");
  li.classList.add("post-item");
  li.innerHTML = `
    <div style="word-break:break-word; max-width:100%; white-space:pre-line;">
      <strong>${title}</strong> - <span class="post-item-message">${message}</span> <em>(${audience})</em>
    </div>
  <button class="delete-post" title="Remove post"><i class='ri-close-line' style='font-size:18px; vertical-align:middle;'></i></button>
  `;

  // Add delete functionality with confirmation
  li.querySelector(".delete-post").addEventListener("click", () => {
    if (confirm("Are you sure you want to delete this post?")) {
      li.remove();
    }
  });

  postList.appendChild(li);

  postForm.reset();
  closePostModal();
});

// Calendar Setup
const calendarEl = document.getElementById("calendar");
const events = [
  { date: "2025-09-15", name: "General Assembly" },
  { date: "2025-09-22", name: "Leadership Training" },
];

function generateCalendar(year, month) {
  const firstDay = new Date(year, month, 1).getDay();
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  calendarEl.innerHTML = "";

  for (let i = 0; i < firstDay; i++) {
    const blank = document.createElement("div");
    calendarEl.appendChild(blank);
  }

  for (let day = 1; day <= daysInMonth; day++) {
    const dayEl = document.createElement("div");
    const dateStr = `${year}-${String(month + 1).padStart(2, "0")}-${String(
      day
    ).padStart(2, "0")}`;

    dayEl.classList.add("calendar-day");
    dayEl.textContent = day;

    const event = events.find((e) => e.date === dateStr);
    if (event) {
      dayEl.classList.add("event");
      dayEl.setAttribute("data-event", event.name);
      dayEl.addEventListener("click", () => {
        document.querySelector(
          "#attendanceModal h3"
        ).innerText = `Attendance Management – ${event.name}`;
        attendanceModal.style.display = "flex";
      });
    }

    calendarEl.appendChild(dayEl);
  }
}
generateCalendar(2025, 8);
