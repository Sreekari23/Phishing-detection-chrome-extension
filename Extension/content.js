function scanLinksInEmail() {
    const emailLinks = document.querySelectorAll("div[role='link'] a, .ii a");
  
    emailLinks.forEach(link => {
      const href = link.href;
  
      fetch("http://127.0.0.1:8000/check-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: href })
      })
      .then(response => response.json())
      .then(data => {
        if (data.status === "dangerous") {
          link.style.color = "red";
          link.style.border = "2px solid red";
          link.style.backgroundColor = "#ffcccc";
          link.title = "⚠️ Phishing suspected!";
        } else if (data.status === "safe") {
          link.style.color = "green";
          link.title = "✔️ Safe link";
        }
      })
      .catch(error => console.error("Error checking link:", error));
    });
  }
  
  // Re-run every few seconds in case Gmail loads emails dynamically
  setInterval(scanLinksInEmail, 5000);
  