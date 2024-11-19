/***************
 * node-unblocker: Web Proxy for evading firewalls and content filters.
 * 
 * GitHub: https://github.com/nfriedly/nodeunblocker.com
 * Modified by Manny Baez: https://github.com/xMannyGamingx
 * Licensed under the Affero GPL v3
 ***************/

const express = require('express');
const { Transform } = require('stream');
const querystring = require('querystring');
const url = require('url');
const Unblocker = require('unblocker');
const youtube = require('unblocker/examples/youtube/youtube.js');

const app = express();
const google_analytics_id = process.env.GA_ID || null;

// Google Analytics injection middleware
function addGa(html) {
    if (!google_analytics_id) return html;

    const gaScript = `
        <script async src="https://www.googletagmanager.com/gtag/js?id=${google_analytics_id}"></script>
        <script>
            window.dataLayer = window.dataLayer || [];
            function gtag() { dataLayer.push(arguments); }
            gtag('js', new Date());
            gtag('config', '${google_analytics_id}');
        </script>
    `;
    return html.replace("</body>", `${gaScript}\n</body>`);
}

function googleAnalyticsMiddleware(data) {
    if (data.contentType === 'text/html') {
        data.stream = data.stream.pipe(
            new Transform({
                decodeStrings: false,
                transform(chunk, encoding, next) {
                    this.push(addGa(chunk.toString()));
                    next();
                },
            })
        );
    }
}

// Unblocker configuration
const unblocker = new Unblocker({
    prefix: '/proxy/',
    requestMiddleware: [
        youtube.processRequest,
        (req) => {
            // Add headers to bypass common restrictions
            req.headers['x-requested-with'] = 'XMLHttpRequest';
            delete req.headers['x-frame-options'];
            delete req.headers['content-security-policy'];
        },
    ],
    responseMiddleware: [
        googleAnalyticsMiddleware,
        (data) => {
            if (data.contentType.startsWith('text/html')) {
                // Strip X-Frame-Options or CSP for iframe compatibility
                delete data.headers['x-frame-options'];
                delete data.headers['content-security-policy'];
            }
        },
    ],
});

// Use unblocker middleware
app.use(unblocker);

// Static file serving for the public directory
app.use('/', express.static(__dirname + '/public'));

// Handle non-JS users
app.get('/no-js', (req, res) => {
    const site = querystring.parse(url.parse(req.url).query).url || '';
    res.redirect(unblocker.prefix + site);
});

// Start the server
const port = process.env.PORT || 8080;
app.listen(port, () => {
    console.log(`Node unblocker listening at http://localhost:${port}/`);
}).on('upgrade', unblocker.onUpgrade);
