const express = require('express');
const crypto = require('crypto');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const ngrok = require('@ngrok/ngrok');
const ExcelJS = require('exceljs');
const os = require('os'); 

const app = express();
const PORT = 3000;

// --- MAGIC IP AUTO-DETECTOR ---
function getLocalIp() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'localhost';
}

const myIp = getLocalIp();
let BASE_URL = `http://${myIp}:${PORT}`;
console.log(`[SYS] Auto-detected Wi-Fi IP: ${myIp}`);
const GOOGLE_SHEETS_WEBHOOK = "https://script.google.com/macros/s/AKfycbwUg5m7whl_93Iq_NtqWZNewh5IQa7W6Q7elH4ngWwpGKY8pRD5Rd4UeW4xJKLEGi0gew/exec"; 

// --- DATABASE SETUP (The Nuclear Option) ---
const db = new sqlite3.Database('./attendance.db');

db.serialize(() => {
    db.run(`DROP TABLE IF EXISTS attendance`, (err) => {
        if (err) console.error("❌ Failed to drop old table:", err.message);
    });

    db.run(`CREATE TABLE attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sessionId TEXT,
        rollNo TEXT,
        ip TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            console.error("❌ Failed to build new table:", err.message);
        } else {
            console.log("✅ Database rebuilt successfully with the Session ID column!");
        }
    });
});

// --- GLOBAL STATE ---
let tokenInterval; // <-- ADDED: To track the QR loop
let ngrokListener; // <-- ADDED: To track the Ngrok tunnel
let currentSessionId = Date.now().toString(); 
let submittedDevices = new Set(); 
let currentToken = null;
let tokenUses = 0;
let tokenExpiresAt = 0;
let deviceScans = new Set(); 

const MAX_USES = 50; 
// ⚠️ Set to 60000 for testing. CHANGE TO 8000 BEFORE LIVE CLASS!
const TOKEN_LIFESPAN_MS = 10000;
const DELAY_DEFENSE_MS = 2;   

// --- TOKEN GENERATOR ---
function generateNewToken() {
    currentToken = crypto.randomBytes(8).toString('hex');
    tokenUses = 0;
    tokenExpiresAt = Date.now() + TOKEN_LIFESPAN_MS;
    deviceScans.clear(); 
    console.log(`[SYS] New Token Generated: ${currentToken}`);
}

generateNewToken();
// <-- FIXED: Save the interval to the variable so we can stop it later
tokenInterval = setInterval(generateNewToken, TOKEN_LIFESPAN_MS);
// --- 🛡️ ROUTE PROTECTION ---
app.use((req, res, next) => {

    const host = req.get('host') || '';

    // Student is allowed only on these routes
    const studentRoutes = [
        '/join',
        '/api/validate',
        '/api/submit'
    ];

    // Professor routes
    const professorRoutes = [
        '/',
        '/index.html',
        '/api/token',
        '/api/download',
        '/api/reset',
        '/api/shutdown'
    ];

    /*
       If request comes from Ngrok:
       - allow students only
       - block professor dashboard
    */
    if (host.includes('ngrok')) {

        if (professorRoutes.includes(req.path)) {

            return res.status(403).send(`
                <html>
                <head>
                    <title>Access Denied</title>
                    <style>
                        body {
                            font-family: Arial;
                            background:#f5f5f5;
                            text-align:center;
                            padding-top:80px;
                        }
                        h1 {
                            color:#d93025;
                            font-size:60px;
                        }
                        p {
                            color:#555;
                            font-size:18px;
                        }
                    </style>
                </head>

                <body>
                    <h1>🛑</h1>
                    <h2>Access Denied</h2>
                    <p>This area is for the Professor only.</p>
                    <p>Please scan the active QR code on the board to mark your attendance.</p>
                </body>
                </html>
            `);
        }
    }

    next();
});

// (Your existing code continues here...)
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());


// 1. Professor Endpoint
app.get('/api/token', (req, res) => {

    // Only professor on local network can access
    const host = req.get('host') || '';

    if (host.includes('ngrok')) {
        return res.status(403).json({
            error:"Professor dashboard cannot be accessed publicly"
        });
    }
});

// 2. Student Entry Point
app.get('/join', (req, res) => {
    if (!req.query.token) return res.status(400).send("Missing token");
    res.sendFile(path.join(__dirname, 'public', 'validate.html'));
});

// 3. Validation Logic (Proxy Blocker)
app.post('/api/validate', async (req, res) => {
    const { token } = req.body;

    if (!token || token !== currentToken) {
        return res.status(400).json({ error: "QR Code Expired. Please scan the current one on the board." });
    }

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const ua = req.headers['user-agent'] || 'unknown';
    const deviceHash = crypto.createHash('sha256').update(ip + ua).digest('hex');

    if (deviceScans.has(deviceHash)) {
        return res.status(400).json({ error: "Your device has already scanned this QR code." });
    }

    if (tokenUses >= MAX_USES) {
        return res.status(400).json({ error: "Capacity reached for this QR cycle." });
    }

    tokenUses++;
    deviceScans.add(deviceHash);

    await new Promise(resolve => setTimeout(resolve, DELAY_DEFENSE_MS));

    if (token !== currentToken) {
        return res.status(400).json({ error: "Validation failed: Token expired during processing." });
    }

    return res.json({ success: true });
});

// 4. Final Submission Endpoint
app.post('/api/submit', async (req, res) => {
    const { token, rollNo, deviceId } = req.body; 
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // --- 🛑 BROWSER BOUNCER ---
    const ua = req.headers['user-agent'] || '';
    const blockedBrowsers = ['OPR', 'Opera', 'Brave', 'DuckDuckGo', 'EdgiOS'];
    
    if (blockedBrowsers.some(b => ua.includes(b))) {
        console.log(`🛡️ BOUNCED: Someone tried to use a VPN browser.`);
        return res.status(400).json({ error: "VPN/Privacy browsers are blocked to prevent cheating. Please use standard Chrome or Safari." });
    }
    
    if (!token || token !== currentToken) {
        return res.status(400).json({ error: "Time expired! You must submit while the QR code is active." });
    }

    console.log(`\n[SCAN CHECK] Roll: ${rollNo} | Device ID: ${deviceId}`);

    if (!deviceId) {
        return res.status(400).json({ error: "Device identification failed. Please try again." });
    }
    
    if (submittedDevices.has(deviceId)) {
        console.log(`🚨 BLOCKED: Device ${deviceId} just tried to submit again!`);
        return res.status(400).json({ error: "Nice try! This phone has already recorded attendance today." });
    }

    const cleanRollNo = rollNo.trim().toUpperCase();

    db.get(`SELECT rollNo FROM attendance WHERE rollNo = ? AND sessionId = ?`, [cleanRollNo, currentSessionId], async (err, row) => {
        if (err) return res.status(500).json({ error: "Database error" });

        if (row) {
            return res.status(400).json({ error: "Attendance already recorded for this Roll Number!" });
        }

        db.run(`INSERT INTO attendance (sessionId, rollNo, ip) VALUES (?, ?, ?)`, [currentSessionId, cleanRollNo, ip], async function(err) {
            if (err) return res.status(500).json({ error: "Database error" });
            
            console.log(`✅ SUCCESS: Roll No: ${cleanRollNo} is marked present.`);
            submittedDevices.add(deviceId); 

            try {
                await fetch(GOOGLE_SHEETS_WEBHOOK, {
                    method: 'POST',
                    body: JSON.stringify({ rollNo: cleanRollNo, deviceIp: ip }),
                    headers: { 'Content-Type': 'application/json' }
                });
            } catch (sheetErr) {
                console.error("⚠️ Google Sheets Backup Failed");
            }

            return res.json({ success: true });
        });
    });
});

// 5. Teacher Export Endpoint 
app.get('/api/download', (req, res) => {
    db.all(`SELECT * FROM attendance`, [], async (err, rows) => {
        if (err) return res.status(500).send("Database error");

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Class Attendance');

        worksheet.columns = [
            { header: 'Timestamp', key: 'timestamp', width: 25 },
            { header: 'Roll Number', key: 'rollNo', width: 15 },
            { header: 'IP Address', key: 'ip', width: 20 }
        ];

        worksheet.getRow(1).font = { bold: true };
        worksheet.addRows(rows);

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename="Attendance_Report.xlsx"');

        await workbook.xlsx.write(res);
        res.end();
    });
});

// 6. Reset Session Endpoint
app.post('/api/reset', (req, res) => {
    db.run(`DELETE FROM attendance`, (err) => {
        if (err) {
            console.error("Failed to clear DB:", err);
            return res.status(500).json({ error: "Failed to clear database" });
        }
        submittedDevices.clear();
        currentSessionId = Date.now().toString(); 
        
        console.log("♻️ SESSION RESET: Database cleared, Devices unblocked, New Session started.");
        res.json({ success: true });
    });
});

// 7. Shutdown Server Endpoint (Graceful Exit)
app.post('/api/shutdown', async (req, res) => {
    res.json({ success: true });
    console.log("🛑 Class ended. Shutting down server...");
    
    // <-- FIXED: Stop the QR loop and disconnect Ngrok safely!
    clearInterval(tokenInterval);
    
    try {
        if (ngrokListener) {
            await ngrokListener.close();
            await ngrok.disconnect();
            await ngrok.kill();
            console.log("🚇 Ngrok tunnel disconnected safely.");
        }
    } catch (e) {
        // Ignore if already closed
    }
    
    setTimeout(() => {
        process.exit(0);
    }, 1000);
});

// --- LAUNCH SERVER & CREATE NGROK TUNNEL ---
app.listen(PORT, async () => {
    console.log(`🚀 Server running locally on port ${PORT}`);
    
    try {
        const NGROK_TOKEN = "3BZIRmrzqXoX7LrqVTVSvwsdyxc_56YvN2JmWXjTP7qeNvwJk"; // <-- PUT YOUR NEW RESET TOKEN HERE!
        
        // <-- FIXED: Save to the global ngrokListener variable
        ngrokListener = await ngrok.forward({
            addr: PORT,
            authtoken: NGROK_TOKEN
        });
        
        BASE_URL = ngrokListener.url();
        
        console.log(`\n======================================================`);
        console.log(`🚇 NGROK STEALTH TUNNEL ACTIVATED:`);
        console.log(`👉 ${BASE_URL}`);
        console.log(`======================================================\n`);
        
    } catch (error) {
        console.error("❌ Failed to start Ngrok tunnel:", error);
    }
});