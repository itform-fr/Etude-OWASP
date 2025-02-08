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

async function loginAndFetch() {
    const pageInstance = await initializeBrowser();
    
    // Check if cookies are available, if not, log in
    if (!cookies) {
        console.log('No valid cookies found, logging in...');
        await pageInstance.goto('http://php-apache/login.php');
        await pageInstance.type('input[name="login"]', 'admin');
        await pageInstance.type('input[name="password"]', 'ComplexeAdminPass123!');
        await pageInstance.click('input[type="submit"]');

        try {
            // Wait for the page to navigate (redirect to presta.php)
            await pageInstance.waitForNavigation({ 
                waitUntil: 'domcontentloaded', 
                timeout: 60000 // Increased timeout
            });
        } catch (error) {
            console.error('Navigation timeout error:', error);
        }

        // Capture cookies after login
        cookies = await pageInstance.cookies();
        console.log('Cookies after login:', cookies);
    } else {
        // If cookies are available, set them to the page
        console.log('Using existing cookies...');
        await pageInstance.setCookie(...cookies);
    }

    // Now navigate to profile.php?id=2
    await pageInstance.goto('http://php-apache/profile.php?id=2');

    // Wait for the "showDescription" button to appear before clicking
    await pageInstance.waitForSelector('input[name="showDescription"]', { timeout: 60000 });

    // Click the "showDescription" button
    await pageInstance.click('input[name="showDescription"]');

    // Wait for the page to update (adjust this based on the actual page flow)
    await pageInstance.waitForSelector('form', { timeout: 60000 });

    // Capture the updated content after the button click
    const content = await pageInstance.content();
    console.log('Updated page content:', content);

    // Check for any <a> tags with href attributes and click them automatically
    const links = await pageInstance.$$eval('a[href]', links =>
        links.filter(link => link.textContent.trim() !== 'Retour') // Filter out "Retour" links
             .map(link => link.href) // Extract href of valid links
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

    // Run loginAndFetch every 2 minutes (120,000ms)
    setInterval(async () => {
        console.log('Running loginAndFetch at', new Date().toISOString());
        await loginAndFetch().catch(console.error);
    }, 120000); // 2 minutes interval
}

// Start the loop
run().catch(console.error);

