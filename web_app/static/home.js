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