import * as http from 'http';
import * as https from 'https';
import * as forge from 'node-forge';
import * as net from 'net';

export interface CA {
    cert: string;
    key: string;
}

export interface Subject {
    C?: string;
    CN?: string;
    L?: string;
    O?: string;
    OU?: string;
    ST?: string;
}

export interface NautiOptions {
    ca: CA;
    subject: Subject;
}

export class Nauti {
    private readonly handleHttpsConnectBind = this.handleHttpsConnect.bind(this);
    private readonly httpServer = http.createServer((req, res) => {
        const targetUrl = new URL(req.url, `http://${req.headers.host}`);
        const proxyReq = http.request(
            targetUrl,
            {
                method: req.method,
                headers: req.headers,
            },
            (proxyRes) => {
                res.writeHead(proxyRes.statusCode, proxyRes.headers);
                proxyRes.pipe(res, { end: true });
            },
        );
        req.pipe(proxyReq, { end: true });
        proxyReq.on('error', () => {
            res.writeHead(500);
            res.end('Proxy error');
        });
    });
    private readonly certCacheMap = new Map<string, CA>();

    public constructor(private readonly options: NautiOptions) {}

    public start(port?: number) {
        this.httpServer.on('connect', this.handleHttpsConnectBind);
        this.httpServer.listen(typeof port === 'number' ? port : 6789);
    }

    public stop() {
        this.httpServer.off('connect', this.handleHttpsConnectBind);
        this.httpServer.close();
    }

    private handleHttpsConnect(request, clientSocket, head) {
        const { hostname } = new URL(`https://${request.url}`);
        const {
            cert,
            key,
        } = this.createCertificate(hostname);
        const httpsServer = https.createServer(
            {
                key,
                cert,
            },
            (proxyRequest, proxyResponse) => {
                const targetUrl = new URL(proxyRequest.url, `https://${proxyRequest.headers.host}`);
                const proxyReq = https.request(
                    targetUrl,
                    {
                        method: proxyRequest.method,
                        headers: proxyRequest.headers,
                    },
                    (proxyRes) => {
                        proxyResponse.writeHead(proxyRes.statusCode, proxyRes.headers);
                        proxyRes.pipe(proxyResponse, { end: true });
                        httpsServer.close();
                    },
                );
                proxyRequest.pipe(proxyReq, { end: true });
                proxyReq.on('error', (err) => {
                    console.error('Proxy request error:', err);
                    proxyResponse.writeHead(500);
                    proxyResponse.end('Proxy error');
                    httpsServer.close();
                });
            },
        );
        httpsServer.listen(0, () => {
            const httpsPort = (httpsServer.address() as net.AddressInfo).port;
            const serverSocket = net.connect(httpsPort, '127.0.0.1', () => {
                clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                serverSocket.write(head);
                serverSocket.pipe(clientSocket);
                clientSocket.pipe(serverSocket);
            });
        });
    }

    private createCertificate(hostname) {
        if (this.certCacheMap.has(hostname)) {
            return this.certCacheMap.get(hostname);
        }

        const keyPair = forge.pki.rsa.generateKeyPair(2048);
        const cert = forge.pki.createCertificate();

        cert.publicKey = keyPair.publicKey;
        cert.serialNumber = (Date.now() * Math.random()).toString(16);
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        cert.setSubject(
            ([
                'C',
                'CN',
                'L',
                'O',
                'OU',
                'ST',
            ] as Array<keyof Subject>)
                .filter((shortName) => typeof this.options?.subject?.[shortName] === 'string' && this.options.subject[shortName].length > 0)
                .map((shortName) => {
                    return {
                        shortName,
                        value: this.options.subject[shortName],
                    };
                }),
        );
        cert.setExtensions([
            {
                name: 'subjectAltName',
                altNames: [
                    {
                        type: 2,
                        value: hostname,
                    },
                ],
            },
        ]);
        cert.setIssuer(forge.pki.certificateFromPem(this.options.ca.cert.toString()).subject.attributes);
        cert.sign(forge.pki.privateKeyFromPem(this.options.ca.key.toString()), forge.md.sha256.create());

        const result: CA = {
            key: forge.pki.privateKeyToPem(keyPair.privateKey),
            cert: forge.pki.certificateToPem(cert),
        };

        this.certCacheMap.set(hostname, result);

        return result;
    }
}
