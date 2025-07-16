document.addEventListener("DOMContentLoaded", () => {
    const selectedHoneypot = localStorage.getItem("selectedHoneypot");
    if (selectedHoneypot) {
        console.log("Selected honeypot:", selectedHoneypot);
        document.getElementById("honeypot-title").textContent = selectedHoneypot;

        const ports = {
            "Ciscoasa": [5000, 8443],
            "Dicompot": [11112],
            "Honeyaml": [8080],
            "Medpot": [2575],
            "SentryPeer": [5060],
            "Abdhoney": [5555],
            "Conpot": [161, 2404, 10001, 623, 1025, 50100],
            "Cowrie": [22, 23],
            "Dionaea": [20, 21, 42, 69, 81, 135, 445, 1433, 1723, 1883, 3306, 27017],
            "Elasticpot": [9200],
            "H0neytr4p": [443],
            "Heralding": [110, 143, 465, 993, 995, 1080, 5432, 5900],
            "Ipphoney": [631],
            "Mailoney": [25, 587],
            "Miniprint": [9100],
            "Redishoneypot": [6379],
            "Wordpot": [80]
        };

        const selectedPorts = ports[selectedHoneypot];
        console.log("Relevant ports:", selectedPorts);
    }
});