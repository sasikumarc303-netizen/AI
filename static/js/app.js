/* Lightweight UI helpers — nothing here blocks app functionality. */
(function () {
  "use strict";

  // Password visibility toggle
  document.querySelectorAll("[data-pw-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-pw-toggle"));
      if (!input) return;
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
    });
  });

  // Disable submit buttons while processing (prevents duplicate submissions)
  document.querySelectorAll("form[data-single-submit]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var btn = form.querySelector("button[type=submit], .btn");
      if (btn) { btn.disabled = true; btn.dataset.orig = btn.textContent; btn.textContent = "Processing…"; }
    });
  });

  // Upload dropzone
  var dz = document.getElementById("dropzone");
  if (dz) {
    var input = document.getElementById("file-input");
    var label = document.getElementById("drop-label");
    var form = document.getElementById("upload-form");
    var progress = document.getElementById("scan-progress");
    var maxBytes = parseInt(dz.dataset.maxBytes || "0", 10);

    function setFile(file) {
      if (!file) return;
      if (maxBytes && file.size > maxBytes) {
        label.textContent = "File is too large (max " + Math.round(maxBytes / 1048576) + " MB).";
        input.value = "";
        return;
      }
      var dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      label.textContent = file.name + " (" + (file.size / 1024).toFixed(1) + " KB) — ready to scan";
    }
    dz.addEventListener("click", function () { input.click(); });
    dz.addEventListener("dragover", function (e) { e.preventDefault(); dz.classList.add("dragover"); });
    dz.addEventListener("dragleave", function () { dz.classList.remove("dragover"); });
    dz.addEventListener("drop", function (e) {
      e.preventDefault(); dz.classList.remove("dragover");
      if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
    });
    input.addEventListener("change", function () { if (input.files.length) setFile(input.files[0]); });
    if (form) form.addEventListener("submit", function () {
      if (progress) progress.style.display = "block";
    });
  }

  // Debounced auto-submit for history search
  var search = document.getElementById("history-search");
  if (search) {
    var t;
    search.addEventListener("input", function () {
      clearTimeout(t);
      t = setTimeout(function () { search.form.submit(); }, 450);
    });
  }

  // Doughnut chart (no external dependency)
  var canvas = document.getElementById("threat-chart");
  if (canvas) {
    var data = JSON.parse(canvas.dataset.values || "[]");
    var colors = ["#22c55e", "#f59e0b", "#ef4444", "#94a3b8", "#64748b"];
    var labels = ["Safe", "Suspicious", "Malware", "Unknown", "Error"];
    var total = data.reduce(function (a, b) { return a + b; }, 0);
    var ctx = canvas.getContext("2d");
    var cx = canvas.width / 2, cy = canvas.height / 2, r = Math.min(cx, cy) - 8;
    if (total === 0) {
      ctx.fillStyle = "#8ea0b8"; ctx.font = "13px sans-serif"; ctx.textAlign = "center";
      ctx.fillText("No scans yet", cx, cy);
    } else {
      var angle = -Math.PI / 2;
      data.forEach(function (v, i) {
        if (!v) return;
        var slice = (v / total) * Math.PI * 2;
        ctx.beginPath(); ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, angle, angle + slice); ctx.closePath();
        ctx.fillStyle = colors[i]; ctx.fill();
        angle += slice;
      });
      ctx.globalCompositeOperation = "destination-out";
      ctx.beginPath(); ctx.arc(cx, cy, r * 0.55, 0, Math.PI * 2); ctx.fill();
      ctx.globalCompositeOperation = "source-over";
      ctx.fillStyle = "#e2e8f0"; ctx.font = "bold 18px sans-serif"; ctx.textAlign = "center";
      ctx.fillText(total, cx, cy + 6);
    }
    var legend = document.getElementById("threat-legend");
    if (legend) {
      legend.innerHTML = labels.map(function (l, i) {
        return '<span style="margin-right:12px"><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:' +
          colors[i] + ';margin-right:5px"></span>' + l + " (" + (data[i] || 0) + ")</span>";
      }).join("");
    }
  }

  // Confirm destructive actions
  document.querySelectorAll("[data-confirm]").forEach(function (el) {
    el.addEventListener("click", function (e) {
      if (!window.confirm(el.getAttribute("data-confirm"))) e.preventDefault();
    });
  });
})();
