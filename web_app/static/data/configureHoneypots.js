// Use this file to update honeypot sentence summaries and port information.

function getHoneypotSentenceSummary(selectedHoneypot) {
    const honeypotSentences = {
        "Ciscoasa": "Low Interaction. Simulates a vulnerable Cisco Adaptive Security Appliance (ASA) firewall to attract and analyze attacks targeting Cisco network infrastructure.",
        "Dicompot": "Low Interaction. Digital Imaging and Communications in Medicine (DICOM) Honeypot",
        "Honeyaml": "Low Interaction. Simulates a vulnerable API server.",
        "Medpot": "Low Interaction. Simulates HL7 FHIR (Fast Healthcare Interoperability Resources).",
        "SentryPeer": "Low Interaction. A fraud detection honeypot for logging attackers over VoIP",
        "Abdhoney": "Low Interaction. A honeypot for Android Debug Bridge over TCP/IP.",
        "Conpot": "Low Interaction. A server side ICS honeypot.",
        "Cowrie": "Medium-High Interaction. An SSH/Telnet honeypot.",
        "Dionaea": "Low Interaction. Detects shellcodes (small piece of code used as the payload in the exploitation of a software vulnerability). Emulates vulnerable services like SMB, HTTP, FTP, TFTP, MSSQL, MySQL, SIP, etc.",
        "Elasticpot": "Low Interaction. Simulates an Elasticsearch server opened to the Internet.",
        "H0neytr4p": "Low Interaction. This HTTP honeypot protects against web recon and exploits.",
        "Honeytrap": "Low Interaction. Monitors attacks on TCP/UDP ports. Logs malicious traffic sent by attackers.",
        "Heralding": "Low Interaction. Collects credentials over ftp, telnet, ssh, http, and more.",
        "Ipphoney": "Low Interaction. Simulates a printer that uses Internet Printing Protocol.",
        "Mailoney": "Low Interaction SMTP honeypot that simulates a mail server to log email attacks.",
        "Miniprint": "Medium Interaction. Simulates a printer accidentally exposed to the internet with PJL (Printer Job Language).",
        "Redishoneypot": "High Interactive honeypot for the Redis protocol.",
        "Wordpot": "Low Interaction honeypot that simulates a Wordpress installation."
    };

    try {
        return honeypotSentences[selectedHoneypot];
    }

    catch {
        return "Invalid selection";
    }
}

function getPortsByType(mode = null, selectHoneypot = null) {
    // Raw honeypot -> ports mapping
    const portsByHoneypot = [
        ["Ciscoasa", [5000, 8443]],
        ["Dicompot", [11112]],
        ["Honeyaml", [8080]],
        ["Medpot", [2575]],
        ["SentryPeer", [5060]],
        ["Abdhoney", [5555]],
        ["Conpot", [161, 2404, 10001, 623, 1025, 50100]],
        ["Cowrie", [22, 23]],
        ["Dionaea", [20, 21, 42, 69, 81, 135, 445, 1433, 1723, 1883, 3306, 27017]],
        ["Elasticpot", [9200]],
        ["H0neytr4p", [443]],
        ["Heralding", [110, 143, 465, 993, 995, 1080, 5432, 5900]],
        ["Ipphoney", [631]],
        ["Mailoney", [25, 587]],
        ["Miniprint", [9100]],
        ["Redishoneypot", [6379]],
        ["Wordpot", [80]],
        ["Honeytrap", ["Ports not covered by other honeypots."]]
    ];

    let filteredData = portsByHoneypot;
    if (selectHoneypot !== null) {
        const found = portsByHoneypot.find(([name]) => name === selectHoneypot);
        return found ? found[1] : [];  // just return [22, 23] etc.
    }

    if (mode === "scatter") {
        // Scatter format: [{ x: honeypot, y: port }]
        return portsByHoneypot.flatMap(([honeypot, ports]) =>
            ports.map(port => ({
                x: honeypot,
                y: port
            }))
        );
    }
    else if (mode === "bar") {
        // Bar format: { honeypotName: numPorts }
        const barData = {};
        portsByHoneypot.forEach(([honeypot, ports]) => {
            barData[honeypot] = ports.length; // number of ports per honeypot
        });
        return barData;
    }
    else {
        console.error("Invalid mode for getPortsByType:", mode);
        return mode === "bar" ? {} : [];
    }
}