
'use strict';

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const ExcelJS = require('exceljs');
const os = require('os');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, 'public');
const DB_PATH = path.join(__dirname, 'attendance.db');

const TOKEN_LIFESPAN_MS = 12000;
const MAX_USES = 50;

// Optional configuration through environment variables.
// Do not put credentials directly in this file.
const NGROK_AUTHTOKEN = process.env.NGROK_AUTHTOKEN || '';
const GOOGLE_SHEETS_WEBHOOK =
    process.env.GOOGLE_SHEETS_WEBHOOK || '';

const EXPLICIT_BASE_URL = process.env.PUBLIC_BASE_URL || '';

app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));

// --------------------------------------------------
// LOCAL IP DETECTION
// --------------------------------------------------

function getLocalIp() {
    const interfaces = os.networkInterfaces();
    const candidates = [];

    for (const [name, entries] of Object.entries(interfaces)) {
        for (const iface of entries || []) {
            if (iface.family !== 'IPv4' || iface.internal) {
                continue;
            }

            const ip = iface.address;

            const isPrivate =
                /^10\./.test(ip) ||
                /^192\.168\./.test(ip) ||
                /^172\.(1[6-9]|2\d|3[01])\./.test(ip);

            candidates.push({
                name,
                ip,
                isPrivate
            });
        }
    }

    // On most Macs, en0 is the Wi-Fi interface.
    const wifi = candidates.find(item => item.name === 'en0');

    if (wifi) return wifi.ip;

    const privateAddress = candidates.find(item => item.isPrivate);

    return privateAddress?.ip ||
        candidates[0]?.ip ||
        'localhost';
}

const myIp = getLocalIp();

let BASE_URL = (
    EXPLICIT_BASE_URL ||
    `http://${myIp}:${PORT}`
).replace(/\/+$/, '');

let ngrokListener = null;
let tokenInterval = null;
let server = null;
let shuttingDown = false;

console.log(`[SYS] Detected local IP: ${myIp}`);

// --------------------------------------------------
// DATABASE
// Never drop the attendance table on startup.
// Existing attendance records are preserved.
// --------------------------------------------------

const db = new sqlite3.Database(DB_PATH);

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) {
                reject(err);
            } else {
                resolve({
                    changes: this.changes,
                    lastID: this.lastID
                });
            }
        });
    });
}

function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

async function initializeDatabase() {
    await dbRun(`
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sessionId TEXT NOT NULL,
            rollNo TEXT NOT NULL,
            ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await dbRun(`
        CREATE INDEX IF NOT EXISTS idx_attendance_session_roll
        ON attendance(sessionId, rollNo)
    `);

    await dbRun(`
        CREATE INDEX IF NOT EXISTS idx_attendance_session_ip
        ON attendance(sessionId, ip)
    `);

    console.log('[DB] Attendance database ready.');
}

// --------------------------------------------------
// SESSION AND TOKEN STATE
// --------------------------------------------------

let currentSessionId = crypto.randomUUID();
let sessionActive = true;

let currentToken = '';
let tokenUses = 0;
let tokenExpiresAt = 0;

const submittedDevices = new Set();
const deviceScans = new Set();
const validatedDevices = new Set();

// Track submissions already in progress so Stop Session
// can wait for them before returning its confirmation.
let inFlightSubmissions = 0;
let submissionWaiters = [];

function beginSubmission() {
    inFlightSubmissions++;
}

function endSubmission() {
    inFlightSubmissions--;

    if (inFlightSubmissions === 0) {
        const waiters = submissionWaiters;
        submissionWaiters = [];

        for (const resolve of waiters) {
            resolve();
        }
    }
}

function waitForSubmissions() {
    if (inFlightSubmissions === 0) {
        return Promise.resolve();
    }

    return new Promise(resolve => {
        submissionWaiters.push(resolve);
    });
}

// --------------------------------------------------
// TOKEN GENERATION
// --------------------------------------------------

function generateNewToken() {
    if (!sessionActive) return;

    currentToken = crypto.randomBytes(16).toString('hex');
    tokenUses = 0;
    tokenExpiresAt = Date.now() + TOKEN_LIFESPAN_MS;

    deviceScans.clear();
    validatedDevices.clear();

    console.log(
        `[QR] Token refreshed. Expires at ${
            new Date(tokenExpiresAt).toLocaleTimeString()
        }`
    );
}

function startTokenLoop() {
    if (tokenInterval) {
        clearInterval(tokenInterval);
    }

    generateNewToken();

    tokenInterval = setInterval(
        generateNewToken,
        TOKEN_LIFESPAN_MS
    );
}

function stopTokenLoop() {
    if (tokenInterval) {
        clearInterval(tokenInterval);
        tokenInterval = null;
    }
}

function tokenIsActive(token) {
    return Boolean(
        sessionActive &&
        typeof token === 'string' &&
        token.length > 0 &&
        token === currentToken &&
        Date.now() < tokenExpiresAt
    );
}

startTokenLoop();

// --------------------------------------------------
// CLIENT IP
// --------------------------------------------------

function isPublicTunnelRequest(req) {
    const host = (req.get('host') || '').toLowerCase();
    const forwardedHost =
        (req.get('x-forwarded-host') || '').toLowerCase();

    return (
        host.includes('ngrok') ||
        forwardedHost.includes('ngrok')
    );
}

function getRequestIp(req) {
    let ip;

    // Use the forwarded address only for a request arriving
    // through the configured public tunnel.
    if (isPublicTunnelRequest(req)) {
        const forwarded = req.get('x-forwarded-for');

        if (forwarded) {
            ip = forwarded.split(',')[0].trim();
        }
    }

    if (!ip) {
        ip = req.socket?.remoteAddress || 'unknown';
    }

    // Normalize IPv4-mapped IPv6 addresses.
    if (ip.startsWith('::ffff:')) {
        ip = ip.slice(7);
    }

    return ip;
}

function getDeviceHash(req) {
    const ip = getRequestIp(req);
    const ua = req.get('user-agent') || 'unknown';

    return crypto
        .createHash('sha256')
        .update(`${ip}|${ua}`)
        .digest('hex');
}

// --------------------------------------------------
// CHROME USER-AGENT CHECK
// This is a basic filter, not proof of browser identity.
// --------------------------------------------------

function isChromeBrowser(req) {
    const ua = req.get('user-agent') || '';

    const isChrome = /(?:Chrome|CriOS)\/[\d.]+/.test(ua);

    const isAnotherBrowser =
        /Edg(?:e|A|iOS)?\/|OPR\/|Opera|Firefox\/|FxiOS\/|SamsungBrowser\/|DuckDuckGo|YaBrowser|Vivaldi/i
            .test(ua);

    return isChrome && !isAnotherBrowser;
}

function requireChrome(req, res) {
    if (isChromeBrowser(req)) {
        return true;
    }

    res.status(403).json({
        error: 'Please use Google Chrome to mark attendance.'
    });

    return false;
}

// --------------------------------------------------
// PUBLIC TUNNEL PROTECTION
// Students may access /join, /api/validate and /api/submit.
// Professor APIs and the dashboard are blocked over Ngrok.
// --------------------------------------------------

const professorPaths = new Set([
    '/',
    '/index.html',
    '/api/token',
    '/api/attendance',
    '/api/download',
    '/api/reset',
    '/api/stop-session',
    '/api/shutdown'
]);

app.use((req, res, next) => {
    const normalizedPath =
        req.path.replace(/\/+$/, '') || '/';

    if (
        isPublicTunnelRequest(req) &&
        professorPaths.has(normalizedPath)
    ) {
        return res.status(403).send(`
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <title>Access Denied</title>
            </head>
            <body style="font-family:Arial;text-align:center;padding:60px">
                <h1>Access Denied</h1>
                <p>The professor dashboard is not publicly accessible.</p>
            </body>
            </html>
        `);
    }

    next();
});

// --------------------------------------------------
// STATIC FRONTEND
// --------------------------------------------------

app.use(express.static(PUBLIC_DIR, {
    setHeaders(res, filePath) {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-store');
        }
    }
}));

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get('/api/health', (req, res) => {
    res.set('Cache-Control', 'no-store');

    res.json({
        success: true,
        status: 'ok',
        sessionActive
    });
});

// --------------------------------------------------
// PROFESSOR: CURRENT TOKEN API
// This endpoint always responds with JSON.
// --------------------------------------------------

app.get('/api/token', (req, res) => {
    if (isPublicTunnelRequest(req)) {
        return res.status(403).json({
            error: 'Professor dashboard is local only.'
        });
    }

    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.set('Pragma', 'no-cache');

    const joinUrl = sessionActive
        ? `${BASE_URL}/join?token=${encodeURIComponent(currentToken)}`
        : null;

    return res.json({
        success: true,
        active: sessionActive,
        token: sessionActive ? currentToken : null,
        expiresAt: sessionActive ? tokenExpiresAt : 0,
        joinUrl,
        url: joinUrl
    });
});

// --------------------------------------------------
// STUDENT JOIN PAGE
// The link may contain a token, or the page can show
// its camera scanner when no token is supplied.
// --------------------------------------------------

app.get('/join', (req, res) => {
    res.set('Cache-Control', 'no-store');

    if (!sessionActive) {
        return res.status(403).send(
            'Attendance is closed. Please contact your professor.'
        );
    }

    return res.sendFile(
        path.join(PUBLIC_DIR, 'validate.html'),
        err => {
            if (err && !res.headersSent) {
                console.error('[JOIN] Page error:', err.message);

                res.status(500).send(
                    'Could not load the student attendance page.'
                );
            }
        }
    );
});

// --------------------------------------------------
// STUDENT: VALIDATE QR TOKEN
// --------------------------------------------------

app.post('/api/validate', async (req, res) => {
    if (!sessionActive) {
        return res.status(403).json({
            error: 'Attendance is closed.'
        });
    }

    if (!requireChrome(req, res)) return;

    const { token } = req.body || {};

    if (!tokenIsActive(token)) {
        return res.status(400).json({
            error: 'QR code expired. Scan the current code.'
        });
    }

    if (tokenUses >= MAX_USES) {
        return res.status(400).json({
            error: 'Capacity reached for this QR cycle.'
        });
    }

    const ip = getRequestIp(req);
    const deviceHash = getDeviceHash(req);

    if (deviceScans.has(deviceHash)) {
        return res.status(400).json({
            error: 'This device has already scanned this QR code.'
        });
    }

    // Reserve this device for the current token while the
    // database check runs, avoiding duplicate parallel scans.
    deviceScans.add(deviceHash);

    try {
        const duplicateIp = await dbGet(
            `SELECT rollNo
             FROM attendance
             WHERE sessionId = ? AND ip = ?
             LIMIT 1`,
            [currentSessionId, ip]
        );

        if (!sessionActive || !tokenIsActive(token)) {
            return res.status(400).json({
                error: 'QR code expired during validation.'
            });
        }

        if (duplicateIp) {
            return res.status(400).json({
                error: 'Attendance has already been recorded from this IP address.'
            });
        }

        tokenUses++;
        validatedDevices.add(deviceHash);

        return res.json({
            success: true,
            expiresAt: tokenExpiresAt
        });
    } catch (err) {
        console.error('[VALIDATE] Database error:', err.message);

        deviceScans.delete(deviceHash);

        return res.status(500).json({
            error: 'Could not validate attendance.'
        });
    }
});

// --------------------------------------------------
// STUDENT: FINAL ATTENDANCE SUBMISSION
// Duplicate roll numbers and IPs are checked atomically
// by SQLite to reduce race conditions.
// --------------------------------------------------

app.post('/api/submit', async (req, res) => {
    if (!sessionActive) {
        return res.status(403).json({
            error: 'Attendance is closed.'
        });
    }

    if (!requireChrome(req, res)) return;

    const { token, rollNo, deviceId } = req.body || {};

    if (!tokenIsActive(token)) {
        return res.status(400).json({
            error: 'QR expired. Scan the latest classroom QR code.'
        });
    }

    if (typeof rollNo !== 'string' || !rollNo.trim()) {
        return res.status(400).json({
            error: 'Enter a valid roll number.'
        });
    }

    if (
        typeof deviceId !== 'string' ||
        !deviceId.trim() ||
        deviceId.length > 200
    ) {
        return res.status(400).json({
            error: 'Device identification failed. Please try again.'
        });
    }

    const cleanRollNo = rollNo.trim().toUpperCase();
    const cleanDeviceId = deviceId.trim();
    const ip = getRequestIp(req);
    const deviceHash = getDeviceHash(req);

    if (submittedDevices.has(cleanDeviceId)) {
        return res.status(400).json({
            error: 'This device has already recorded attendance in this session.'
        });
    }

    if (!validatedDevices.has(deviceHash)) {
        return res.status(400).json({
            error: 'Validate the current QR code before submitting attendance.'
        });
    }

    // Consume the validation so one successful scan cannot be
    // reused for multiple submissions.
    validatedDevices.delete(deviceHash);

    beginSubmission();

    try {
        // Stop Session invalidates the token immediately.
        if (!tokenIsActive(token)) {
            return res.status(400).json({
                error: 'Attendance session stopped or QR expired.'
            });
        }

        // Atomic insert-if-no-duplicate:
        // reject either the same roll number or the same IP
        // within the current session.
        const result = await dbRun(
            `INSERT INTO attendance (sessionId, rollNo, ip)
             SELECT ?, ?, ?
             WHERE NOT EXISTS (
                 SELECT 1
                 FROM attendance
                 WHERE sessionId = ?
                   AND (rollNo = ? OR ip = ?)
             )`,
            [
                currentSessionId,
                cleanRollNo,
                ip,
                currentSessionId,
                cleanRollNo,
                ip
            ]
        );

        if (result.changes === 0) {
            const duplicate = await dbGet(
                `SELECT rollNo, ip
                 FROM attendance
                 WHERE sessionId = ?
                   AND (rollNo = ? OR ip = ?)
                 LIMIT 1`,
                [currentSessionId, cleanRollNo, ip]
            );

            if (duplicate && duplicate.rollNo === cleanRollNo) {
                return res.status(409).json({
                    error: 'Attendance is already recorded for this roll number.'
                });
            }

            if (duplicate && duplicate.ip === ip) {
                return res.status(409).json({
                    error: 'Attendance has already been recorded from this IP address.'
                });
            }

            return res.status(409).json({
                error: 'Attendance could not be recorded. Please try again.'
            });
        }

        submittedDevices.add(cleanDeviceId);

        console.log(
            `[ATTENDANCE] Present: ${cleanRollNo} | IP: ${ip}`
        );

        // Optional Google Sheets backup.
        if (GOOGLE_SHEETS_WEBHOOK) {
            try {
                const response = await fetch(
                    GOOGLE_SHEETS_WEBHOOK,
                    {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            rollNo: cleanRollNo,
                            deviceIp: ip,
                            sessionId: currentSessionId
                        }),
                        signal: AbortSignal.timeout(5000)
                    }
                );

                if (!response.ok) {
                    console.error(
                        '[SHEETS] Backup returned HTTP',
                        response.status
                    );
                }
            } catch (err) {
                console.error(
                    '[SHEETS] Backup failed:',
                    err.message
                );
            }
        }

        return res.json({
            success: true,
            rollNo: cleanRollNo
        });
    } catch (err) {
        console.error('[SUBMIT] Error:', err.message);

        return res.status(500).json({
            error: 'Could not save attendance.'
        });
    } finally {
        endSubmission();
    }
});

// --------------------------------------------------
// PROFESSOR: LIVE ATTENDANCE LIST
// The frontend can poll this endpoint every two seconds.
// --------------------------------------------------

app.get('/api/attendance', async (req, res) => {
    if (isPublicTunnelRequest(req)) {
        return res.status(403).json({
            error: 'Professor dashboard is local only.'
        });
    }

    try {
        const rows = await dbAll(
            `SELECT timestamp, rollNo, ip
             FROM attendance
             WHERE sessionId = ?
             ORDER BY id DESC`,
            [currentSessionId]
        );

        res.set('Cache-Control', 'no-store');

        return res.json({
            success: true,
            active: sessionActive,
            count: rows.length,
            attendance: rows
        });
    } catch (err) {
        console.error('[ATTENDANCE LIST]', err.message);

        return res.status(500).json({
            error: 'Could not load attendance.'
        });
    }
});

// --------------------------------------------------
// PROFESSOR: DOWNLOAD EXCEL
// Downloads attendance for the current session only.
// --------------------------------------------------

app.get('/api/download', async (req, res) => {
    if (isPublicTunnelRequest(req)) {
        return res.status(403).send(
            'Professor downloads are local only.'
        );
    }

    try {
        const rows = await dbAll(
            `SELECT timestamp, rollNo, ip
             FROM attendance
             WHERE sessionId = ?
             ORDER BY id ASC`,
            [currentSessionId]
        );

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Class Attendance');

        worksheet.columns = [
            {
                header: 'Timestamp',
                key: 'timestamp',
                width: 25
            },
            {
                header: 'Roll Number',
                key: 'rollNo',
                width: 18
            },
            {
                header: 'IP Address',
                key: 'ip',
                width: 22
            }
        ];

        worksheet.getRow(1).font = { bold: true };

        for (const row of rows) {
            worksheet.addRow({
                timestamp: row.timestamp,
                rollNo: row.rollNo,
                ip: row.ip
            });
        }

        worksheet.autoFilter = {
            from: 'A1',
            to: 'C1'
        };

        const buffer = await workbook.xlsx.writeBuffer();

        res.setHeader(
            'Content-Type',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        );

        res.setHeader(
            'Content-Disposition',
            'attachment; filename="Attendance_Report.xlsx"'
        );

        res.setHeader('Cache-Control', 'no-store');

        return res.send(Buffer.from(buffer));
    } catch (err) {
        console.error('[EXPORT]', err.message);

        if (!res.headersSent) {
            return res.status(500).send(
                'Could not create the attendance report.'
            );
        }
    }
});

// --------------------------------------------------
// PROFESSOR: STOP QR AND CLOSE ATTENDANCE
// The dashboard should call this endpoint first, wait
// for the JSON response, then navigate to /api/download.
// --------------------------------------------------

app.post('/api/stop-session', async (req, res) => {
    if (isPublicTunnelRequest(req)) {
        return res.status(403).json({
            error: 'Professor dashboard is local only.'
        });
    }

    if (sessionActive) {
        sessionActive = false;

        stopTokenLoop();

        currentToken = '';
        tokenExpiresAt = 0;
        tokenUses = 0;

        deviceScans.clear();
        validatedDevices.clear();

        console.log('[SESSION] QR stopped. Attendance closed.');
    }

    // Wait for already-started submissions to finish before
    // allowing the frontend to download the final report.
    await waitForSubmissions();

    return res.json({
        success: true,
        active: false,
        message: 'Attendance stopped. The final report is ready.'
    });
});

// --------------------------------------------------
// PROFESSOR: START A NEW SESSION
// Previous database rows are retained. The new session
// starts with a new session ID and an empty attendance list.
// --------------------------------------------------

app.post('/api/reset', (req, res) => {
    if (isPublicTunnelRequest(req)) {
        return res.status(403).json({
            error: 'Professor dashboard is local only.'
        });
    }

    sessionActive = false;
    stopTokenLoop();

    // Use a new session rather than deleting historical rows.
    currentSessionId = crypto.randomUUID();

    submittedDevices.clear();
    deviceScans.clear();
    validatedDevices.clear();

    sessionActive = true;
    startTokenLoop();

    console.log('[SESSION] New attendance session started.');

    return res.json({
        success: true,
        active: true,
        sessionId: currentSessionId
    });
});

// --------------------------------------------------
// OPTIONAL: SHUT DOWN THE ENTIRE SERVER
// Different from Stop QR, which leaves the server running.
// --------------------------------------------------

app.post('/api/shutdown', (req, res) => {
    if (isPublicTunnelRequest(req)) {
        return res.status(403).json({
            error: 'Server shutdown is local only.'
        });
    }

    res.json({
        success: true,
        message: 'Server is shutting down.'
    });

    setTimeout(() => {
        shutdown();
    }, 100);
});

// --------------------------------------------------
// GRACEFUL SHUTDOWN
// --------------------------------------------------

async function shutdown() {
    if (shuttingDown) return;

    shuttingDown = true;
    sessionActive = false;

    stopTokenLoop();

    currentToken = '';
    tokenExpiresAt = 0;

    await waitForSubmissions();

    if (ngrokListener) {
        try {
            await ngrokListener.close();
            ngrokListener = null;
            console.log('[NGROK] Tunnel closed.');
        } catch (err) {
            console.error('[NGROK] Close warning:', err.message);
        }
    }

    if (server && server.listening) {
        await new Promise(resolve => server.close(resolve));
    }

    db.close(err => {
        if (err) {
            console.error('[DB] Close error:', err.message);
            process.exit(1);
        }

        console.log('[SYS] Server stopped.');
        process.exit(0);
    });

    setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// --------------------------------------------------
// START SERVER ONLY AFTER DATABASE INITIALIZATION
// --------------------------------------------------

async function startServer() {
    try {
        await initializeDatabase();

        server = app.listen(PORT, '0.0.0.0', async () => {
            console.log('');
            console.log('========================================');
            console.log(' ATTENDANCE SERVER RUNNING');
            console.log('========================================');
            console.log(` Dashboard: http://localhost:${PORT}`);
            console.log(` LAN URL:   http://${myIp}:${PORT}`);
            console.log(` Token API: http://localhost:${PORT}/api/token`);
            console.log(` Health:    http://localhost:${PORT}/api/health`);
            console.log('========================================');

            if (!NGROK_AUTHTOKEN) {
                console.log(
                    '[NGROK] Disabled. Local Wi-Fi hosting is active.'
                );

                console.log(
                    `[QR] Student URL base: ${BASE_URL}`
                );

                return;
            }

            try {
                const ngrok = require('@ngrok/ngrok');

                ngrokListener = await ngrok.forward({
                    addr: PORT,
                    authtoken: NGROK_AUTHTOKEN
                });

                const tunnelUrl = ngrokListener.url();

                if (tunnelUrl) {
                    BASE_URL = tunnelUrl.replace(/\/+$/, '');
                }

                console.log('[NGROK] Tunnel started.');
                console.log(`[NGROK] Student URL base: ${BASE_URL}`);
                console.log(
                    '[NGROK] The professor dashboard remains local only.'
                );
            } catch (err) {
                console.error(
                    '[NGROK] Could not start tunnel:',
                    err.message
                );

                console.log(
                    '[SYS] Continuing with local hosting.'
                );
            }
        });

        server.on('error', err => {
            if (err.code === 'EADDRINUSE') {
                console.error(
                    `[SYS] Port ${PORT} is already in use. Stop the other server first.`
                );
            } else {
                console.error('[SYS] Server error:', err.message);
            }
        });
    } catch (err) {
        console.error('[SYS] Failed to initialize database:', err.message);

        db.close(() => process.exit(1));
    }
}

startServer();
