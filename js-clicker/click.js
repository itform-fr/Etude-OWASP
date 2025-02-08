const puppeteer = require('puppeteer');

let browser;
let page;
let cookies;

async function initializeBrowser() {
    if (!browser) {
        browser = await puppeteer.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu']
        });
    }
    if (!page) {
        page = await browser.newPage();
    }
    return page;
}

async function hasValidCookies(pageInstance) {
    cookies = await pageInstance.cookies();
    console.log('Existing Cookies:', cookies);

    const hasPHPSESSID = cookies.some(cookie => cookie.name === 'PHPSESSID');
    const hasAuth = cookies.some(cookie => cookie.name === 'auth');

    return hasPHPSESSID && hasAuth;
}

async function loginAndFetch() {
    const pageInstance = await initializeBrowser();

    if (!(await hasValidCookies(pageInstance))) {
        console.log('No valid PHPSESSID or auth cookie found, logging in...');
        await pageInstance.goto('http://php-apache/login.php');
        await pageInstance.type('input[name="login"]', 'admin');
        await pageInstance.type('input[name="password"]', 'ComplexeAdminPass123!');
        await pageInstance.click('input[type="submit"]');

        try {
            await pageInstance.waitForNavigation({
                waitUntil: 'domcontentloaded',
                timeout: 60000
            });
        } catch (error) {
            console.error('Navigation timeout error:', error);
        }

        // Capture cookies after login
        cookies = await pageInstance.cookies();
        console.log('Cookies after login:', cookies);
    } else {
        console.log('Using existing valid cookies...');
        await pageInstance.setCookie(...cookies);
    }

    // Now navigate to profile.php?id=2
    await pageInstance.goto('http://php-apache/profile.php?id=2');

    await pageInstance.waitForSelector('input[name="showDescription"]', { timeout: 60000 });
    await pageInstance.click('input[name="showDescription"]');

    await pageInstance.waitForSelector('form', { timeout: 60000 });

    const content = await pageInstance.content();
    console.log('Updated page content:', content);

    const links = await pageInstance.$$eval('a[href]', links =>
        links.filter(link => link.textContent.trim() !== 'Retour')
             .map(link => link.href)
    );

    if (links.length > 0) {
        console.log(`Found ${links.length} valid link(s), clicking them...`);
        for (const link of links) {
            await pageInstance.goto(link);
            console.log(`Clicked on link: ${link}`);
        }
    } else {
        console.log('No valid links found after clicking showDescription.');
    }
}

async function run() {
    await initializeBrowser();

    setInterval(async () => {
        console.log('Running loginAndFetch at', new Date().toISOString());
        await loginAndFetch().catch(console.error);
    }, 120000);
}

run().catch(console.error);
