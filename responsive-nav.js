(function () {
  const nav = document.querySelector("nav");
  if (!nav || nav.dataset.mobileNavReady === "true") return;

  nav.dataset.mobileNavReady = "true";

  const themeToggle = document.getElementById("themeToggle");
  if (themeToggle) {
    themeToggle.classList.add("theme-icon-toggle");
    themeToggle.setAttribute("aria-label", "Toggle light and dark theme");
    themeToggle.setAttribute("title", "Toggle theme");
    themeToggle.innerHTML = `
      <svg class="theme-icon theme-icon-sun" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 4.5V2.75M12 21.25V19.5M4.5 12H2.75M21.25 12H19.5M6.7 6.7 5.46 5.46M18.54 18.54 17.3 17.3M17.3 6.7l1.24-1.24M5.46 18.54 6.7 17.3"/>
        <circle cx="12" cy="12" r="4.25"/>
      </svg>
      <svg class="theme-icon theme-icon-moon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M20.2 15.7A8.2 8.2 0 0 1 8.3 3.8 8.5 8.5 0 1 0 20.2 15.7Z"/>
      </svg>
    `;
  }

  const current = window.location.pathname.split("/").pop() || "home2.html";
  const existingLinks = [...nav.querySelectorAll("a[href]")]
    .filter((link) => {
      const label = link.textContent.trim();
      const href = link.getAttribute("href") || "";
      return label && href && !label.toLowerCase().includes("cybershield") && !/detonator/i.test(label) && !/detonator\.html/i.test(href);
    })
    .map((link) => ({
      href: link.getAttribute("href"),
      label: link.textContent.trim().replace(/\s+/g, " ")
    }));

  const fallbackLinks = [
    ["home2.html", "Home"],
    ["analysis.html", "Analysis"],
    ["tools-lab.html", "Tools"],
    ["threat-intel.html", "Threat Intel"],
    ["urlscan.html", "URLScan"],
    ["cases.html", "Cases"],
    ["monitoring.html", "Monitoring"],
    ["reports.html", "Reports"]
  ].map(([href, label]) => ({ href, label }));

  const seen = new Set();
  const links = [...existingLinks, ...fallbackLinks].filter((item) => {
    const key = `${item.href}:${item.label}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "mobile-nav-toggle";
  toggle.setAttribute("aria-label", "Open navigation menu");
  toggle.setAttribute("aria-expanded", "false");
  toggle.innerHTML = "<span></span>";

  const overlay = document.createElement("div");
  overlay.className = "mobile-nav-overlay";

  const drawer = document.createElement("aside");
  drawer.className = "mobile-nav-drawer";
  drawer.setAttribute("aria-label", "Mobile navigation");
  drawer.innerHTML = `
    <div class="mobile-nav-head">
      <p class="mobile-nav-title">CyberShield Menu</p>
      <button type="button" class="mobile-nav-close" aria-label="Close navigation">&times;</button>
    </div>
    <div class="mobile-nav-links">
      ${links.map((item) => {
        const target = String(item.href || "").split("?")[0];
        const active = current === target ? " active" : "";
        return `<a class="${active}" href="${item.href}"><span>${item.label}</span><span>&rsaquo;</span></a>`;
      }).join("")}
    </div>
  `;

  const bottomLinks = [
    { href: "home2.html", label: "Home", icon: "H" },
    { href: "analysis.html", label: "Scan", icon: "S" },
    { href: "tools-lab.html", label: "Tools", icon: "T" },
    { href: "threat-intel.html", label: "Intel", icon: "I" }
  ];

  const bottomNav = document.createElement("nav");
  bottomNav.className = "mobile-bottom-nav";
  bottomNav.setAttribute("aria-label", "Mobile quick navigation");
  bottomNav.innerHTML = `
    <div class="mobile-bottom-nav-links">
      ${bottomLinks.map((item) => {
        const active = current === item.href ? " active" : "";
        return `
          <a class="${active}" href="${item.href}">
            <span class="mobile-bottom-icon">${item.icon}</span>
            <span>${item.label}</span>
          </a>
        `;
      }).join("")}
    </div>
  `;

  nav.appendChild(toggle);
  document.body.appendChild(overlay);
  document.body.appendChild(drawer);
  document.body.appendChild(bottomNav);

  function openMenu() {
    overlay.classList.add("open");
    drawer.classList.add("open");
    toggle.setAttribute("aria-expanded", "true");
  }

  function closeMenu() {
    overlay.classList.remove("open");
    drawer.classList.remove("open");
    toggle.setAttribute("aria-expanded", "false");
  }

  toggle.addEventListener("click", openMenu);
  overlay.addEventListener("click", closeMenu);
  drawer.querySelector(".mobile-nav-close").addEventListener("click", closeMenu);

  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeMenu();
  });
})();
