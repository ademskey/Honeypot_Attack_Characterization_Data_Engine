window.addEventListener("DOMContentLoaded", () => {
    window.addEventListener("click", (e) => {
        if (!e.target.matches(".dropbtn")) {
            const dropdowns = document.getElementsByClassName("dropdown-content");
            for (let i = 0; i < dropdowns.length; i++) {
                dropdowns[i].classList.remove("show");
            }
        }
    });
});

function toggleDropdown() {
    document.getElementById("honeypotDropdown").classList.toggle("show");
}

function selectHoneypot(name) {
    localStorage.setItem("selectedHoneypot", name);
}

async function totalSeconds() {
    return await fetch('/update_time', {
        headers: {
            'X-Requested-By': 'frontend' // request comes from valid frontend.
        }
    });
}

document.addEventListener("DOMContentLoaded", () => {
    // Handle dropdown
    window.addEventListener("click", (e) => {
        if (!e.target.matches(".dropbtn")) {
            const dropdowns = document.getElementsByClassName("dropdown-content");
            for (let i = 0; i < dropdowns.length; i++) {
                dropdowns[i].classList.remove("show");
            }
        }
    });

    function toggleDropdown() {
        document.getElementById("honeypotDropdown").classList.toggle("show");
    }

    function selectHoneypot(name) {
        localStorage.setItem("selectedHoneypot", name);
    }

    // === Progress Bar ===
    const TOTAL_SECONDS = 30;
    let elapsedSeconds = 0;
    let isQuerying = false;

    const progressBar = document.getElementById("progress-bar");
    const progressText = document.getElementById("progress-text");

    function updateProgressBar() {
        if (!isQuerying) {
            elapsedSeconds++;
            if (elapsedSeconds > TOTAL_SECONDS) {
                elapsedSeconds = 0;
            }
        }

        const percent = Math.floor((elapsedSeconds / TOTAL_SECONDS) * 100);
        progressBar.style.width = percent + "%";

        if (isQuerying) {
            progressText.textContent = "Querying new data...";
        } else {
            progressText.textContent = `Time since last update: ${elapsedSeconds}s`;
        }
    }

    function checkUpdateStatus() {
        fetch("/update_status", {
            headers: { 'X-Requested-By': 'frontend' }
        })
            .then(res => res.json())
            .then(data => {
                isQuerying = data.is_querying;  // <-- access property from JSON response
            })
            .catch(err => {
                console.error("Status check failed:", err);
                isQuerying = false;
            });
    }

    setInterval(checkUpdateStatus, 2000);  // Check every 2 seconds
    setInterval(updateProgressBar, 1000);  // Update every second

    // Attach to window for dropdown functions
    window.toggleDropdown = toggleDropdown;
    window.selectHoneypot = selectHoneypot;
});