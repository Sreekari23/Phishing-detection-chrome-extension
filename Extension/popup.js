document.addEventListener("DOMContentLoaded", function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const url = tabs[0].url;
    document.getElementById("url-input1").value = url;
    analyzeEmailContent(url);
  });

  document.getElementById("url-form").addEventListener("submit", function (event) {
    event.preventDefault();
    const url = document.getElementById("url-input1").value;
    analyzeEmailContent(url);
  });
});

function analyzeEmailContent(url) {
  // For demonstration, using placeholders for subject, body, and attachments
  const emailData = {
    subject: "Sample Subject",
    body: "Sample email body containing potential threats.",
    urls: [url],
    attachment_filenames: ["invoice.exe"]
  };

  fetch("http://127.0.0.1:8000/api/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(emailData)
  })
    .then(response => response.json())
    .then(data => {
      const resultDiv = document.getElementsByClassName("result")[0];
      resultDiv.innerHTML = `
        <p><strong>LLM Analysis:</strong></p>
        <p>${data.llm_analysis}</p>
        <p><strong>Phishing URLs:</strong> ${data.phishing_urls.map(item => item.url).join(", ")}</p>
        <p><strong>Suspicious Attachments:</strong> ${data.suspicious_attachments.join(", ")}</p>
      `;
    })
    .catch(error => {
      console.error("Error:", error);
    });
}
