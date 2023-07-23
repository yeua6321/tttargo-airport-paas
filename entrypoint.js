const { execSync } = require('child_process');
const fs = require('fs');

// Install sshd and generate host keys
if (process.env.SSH_PUB_KEY) {
    fs.mkdirSync(`${process.env.HOME}/custom_ssh`);
    const sshdConfig = `
    Port 2222
    HostKey ${process.env.HOME}/custom_ssh/ssh_host_rsa_key
    HostKey ${process.env.HOME}/custom_ssh/ssh_host_dsa_key
    AuthorizedKeysFile  ${process.env.HOME}/.ssh/authorized_keys
    PasswordAuthentication no
    #PermitEmptyPasswords yes
    PermitRootLogin yes
    PubkeyAuthentication yes
    ## Enable DEBUG log.
    LogLevel DEBUG
    ChallengeResponseAuthentication no
    # UsePAM no
    X11Forwarding yes
    PrintMotd no
    AcceptEnv LANG LC_*
    Subsystem   sftp    /usr/lib/ssh/sftp-server
    PidFile ${process.env.HOME}/custom_ssh/sshd.pid
  `;
    fs.writeFileSync(`${process.env.HOME}/custom_ssh/sshd_config`, sshdConfig);

    execSync(`ssh-keygen -f ${process.env.HOME}/custom_ssh/ssh_host_rsa_key -N '' -t rsa`);
    execSync(`ssh-keygen -f ${process.env.HOME}/custom_ssh/ssh_host_dsa_key -N '' -t dsa`);

    fs.mkdirSync(`${process.env.HOME}/.ssh`);
    fs.appendFileSync(`${process.env.HOME}/.ssh/authorized_keys`, process.env.SSH_PUB_KEY);
    fs.appendFileSync(`${process.env.HOME}/.ssh/authorized_keys`, fs.readFileSync(`${process.env.HOME}/custom_ssh/ssh_host_rsa_key.pub`));
    fs.appendFileSync(`${process.env.HOME}/.ssh/authorized_keys`, fs.readFileSync(`${process.env.HOME}/custom_ssh/ssh_host_dsa_key.pub`));

    fs.chmodSync(`${process.env.HOME}/.ssh/authorized_keys`, 0o600);
    fs.chmodSync(`${process.env.HOME}/.ssh`, 0o700);
    fs.chmodSync(`${process.env.HOME}/custom_ssh/*`, 0o600);
    fs.chmodSync(`${process.env.HOME}/custom_ssh/sshd_config`, 0o644);

    execSync(`/usr/sbin/sshd -f ${process.env.HOME}/custom_ssh/sshd_config -D &`);
}

// Set various variables
const WSPATH = process.env.WSPATH || 'argo';
const UUID = process.env.UUID || 'de04add9-5c68-8bab-950c-08cd5320df18';
const MAX_MEMORY_RESTART = process.env.MAX_MEMORY_RESTART || '128M';
const CERT_DOMAIN = process.env.CERT_DOMAIN || 'example.com';
const PANEL_TYPE = process.env.PANEL_TYPE || 'NewV2board';
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || 'example.com';

// Rest of the code...
// Include the crypto module to generate random bytes
const crypto = require('crypto');

const generateRandomName = () => crypto.randomBytes(10).toString('hex');

// Generate random names for echo files
const NEZHA_RANDOMNAME = generateRandomName();
const APPS_RANDOMNAME = generateRandomName();
const WEBJS_RANDOMNAME = generateRandomName();
const ARGO_RANDOMNAME = generateRandomName();

// Add random names to env
process.env.NEZHA_RANDOMNAME = NEZHA_RANDOMNAME;
process.env.APPS_RANDOMNAME = APPS_RANDOMNAME;
process.env.WEBJS_RANDOMNAME = WEBJS_RANDOMNAME;
process.env.ARGO_RANDOMNAME = ARGO_RANDOMNAME;

// 
// const fs = require('fs');
// const { execSync } = require('child_process');

// Function to generate random names
// const generateRandomName = () => crypto.randomBytes(10).toString('hex');
const fs = require('fs');
const path = require('path');

function generate_ca() {
    // Define the paths
    const caKeyPath = path.join(__dirname, 'ca.key');
    const caPemPath = path.join(__dirname, 'ca.pem');

    // Remove the files if they exist
    if (fs.existsSync(caKeyPath)) {
        fs.unlinkSync(caKeyPath);
    }
    if (fs.existsSync(caPemPath)) {
        fs.unlinkSync(caPemPath);
    }

    // Define the contents
    const caKeyContent = `-----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAoGXGNMOZc+DONcimqNM2mU2Xt+cjSWeHRB0V3c2z9ks38ka7
    yXQXUIp8L/4t0YcNNdlAT4KeK1zxaN1NqAfmdkFsZPI5kfd7dGa6+8JG7S3eCc32
    cIxtcysQBF41WyASrglTp64xyLzqMLIMACRjaLm5v+s7+c/2Jn91ohjbeLv7L7fk
    Eh2/xNmYQJm3eeqHN2tgZjP6RiAXjezCe4JD8LDzc8nGMfSvxwuWNNGTr0G27GfP
    WZ4nJeK+FDO1vhkIKX+ENgRu9apnMZO8m37C+VprR1kfc7KGCfjzyTPHZ1/Z04aJ
    peVK2e9xv5tqKmL0VspTEIDQcxVCyAkXr0hqowIDAQABAoIBABZyp+6ygUNqbvGw
    B0MRbE7AQT+HpbScPJ4Xw/uq0kjh9g5+P8HN8YVgHElLNXZhhEPJB+sYyLIg69hV
    QI0HrgVW2qi2DcCT9j8wMXMSmYKQLMcKgDb4MEkx+afi12zNbE/XFlIdWvJRHiV6
    hZtvfEon1As8DMTFihmRNRFekTiwPLgWx8X9zaQq9/Rocn6qEjrLCC1Z4PbkRwu9
    CcZeOUJuX8xiHb1NeFdfaADjZi4/cKu+4WNbjZcz0TlTx5UFDOHUz8GQH5Zdng8y
    4bFAgmyn5maC9HZ+KytsFv4Vm/XJsML8JuNW6jVTF6mj+77r3XekrTD/bBbpH+SK
    fiykYeECgYEA8cafnqxsBOKfaK9C6Yh3Ua45F5t3tUTEcGF2w7ttXM5Ufbmct4li
    q36i3PvyQoKFG1pPFzF7AmnTfVGtU7bbR4ikbzCrMj7CSCr3tD37pgKUjp8rCxPt
    bwHAHNS7HayGmVHITYOsguQ9WlGE0su7VEcunYiVoqp7vCReDhp/78UCgYEAqdWD
    5l3VzSNpEqtXSBtNAHsYE6N9ryhJgzlMMq5xIZ4Stmdk7oVsroRB44btoi6ze6nH
    E2tSHoRr59vzqDrqMIboNjl9YLTAecUMUmGxdFlKL8O34IfjaShlbg948N0wX/i6
    8eeO7VqV7f1Wabzkrwj2HhhB5V+COcgb8gxk70cCgYEAuudIJ9q02oXyo3OxL2WO
    j/c2LXjC7r+NeC7wJ9mxbmgWyuZ9LykmvNp1vo2KNz489es3bv+ST0hN9Pf6HNgj
    5cXNECO4hGwdtrp4qL6t1iTygNqs5LBwATuCLweI6ySfHNErHjknWDxm7XZNTsOu
    OjWY5LFcs9ZFNymKCC8WLd0CgYBQnSzSuE+348sINZRkgbD3PXacO8p4zeK3CweE
    NxE0J9gyBLoADg0ceWLdITrC9O/1Dw2TxilgmvKtR9ZMUErBZgfrVTaSJLoIEuRa
    ZkzZMVjpezlYtqfXTnl22JlLm3JO273A/Wz2dT0djlbqMeNKwjIw7sq4mbEyxC2f
    owp2GQKBgQDi8/BC7GA3DWnBMqYdNBC7qZO0VSSosk8yYkcmzWdpwGhlsGBAdIoT
    j3gFKdJxEtMC95Xw2hOFEkmntJJeSUSX39/aUmunSldzpOVhhKHYCfHXIFHa6f8j
    HpTTb+23vPb2rj8+goBg9Rt18mBRSp9bk8wlxAGIwqHFUrics+i4pA==
    -----END RSA PRIVATE KEY-----`;

    const caPemContent = `-----BEGIN CERTIFICATE-----
    MIIDiTCCAnGgAwIBAgIELyBnuTANBgkqhkiG9w0BAQsFADBbMScwJQYDVQQDDB5SZWdlcnkgU2Vs
    Zi1TaWduZWQgQ2VydGlmaWNhdGUxIzAhBgNVBAoMGlJlZ2VyeSwgaHR0cHM6Ly9yZWdlcnkuY29t
    MQswCQYDVQQGEwJVQTAgFw0yMzAzMjgwMDAwMDBaGA8yMTIzMDMyODEwMjkxOVowSzEXMBUGA1UE
    AwwOd3d3LnJlbmRlci5jb20xIzAhBgNVBAoMGlJlZ2VyeSwgaHR0cHM6Ly9yZWdlcnkuY29tMQsw
    CQYDVQQGEwJVQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKBlxjTDmXPgzjXIpqjT
    NplNl7fnI0lnh0QdFd3Ns/ZLN/JGu8l0F1CKfC/+LdGHDTXZQE+Cnitc8WjdTagH5nZBbGTyOZH3
    e3RmuvvCRu0t3gnN9nCMbXMrEAReNVsgEq4JU6euMci86jCyDAAkY2i5ub/rO/nP9iZ/daIY23i7
    +y+35BIdv8TZmECZt3nqhzdrYGYz+kYgF43swnuCQ/Cw83PJxjH0r8cLljTRk69Btuxnz1meJyXi
    vhQztb4ZCCl/hDYEbvWqZzGTvJt+wvlaa0dZH3Oyhgn488kzx2df2dOGiaXlStnvcb+baipi9FbK
    UxCA0HMVQsgJF69IaqMCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYw
    HQYDVR0OBBYEFHx6uTS/jOqVr7PCuBNhIiCNY0gQMB8GA1UdIwQYMBaAFHx6uTS/jOqVr7PCuBNh
    IiCNY0gQMA0GCSqGSIb3DQEBCwUAA4IBAQB1B4JpJmybk8cfHZr/rng6SGs+pUUUxTEUalVTq9j2
    L39v4d3M/KCNaMLtO4UTWIZ2nqprB0NP2/3ZCiy4fUx9T0xButQjj0YFe00pDgegEDp+NiJ38MBi
    MyFkbXEqJd6ctBM/Qd3jus6DaEsEOvNU/coxViLopntenOdCUfPF31eH5B+myV8XmZxg3tKw2FU9
    1EIiTl3gYrnFvY0kMQcp9MWYv/Njl7MSPGvunllNRjeMt/iVq+4X2t3p1ANAURQqKmL/fy79JSDS
    TYehJJQC3B5VipbnQNtykE6TQJZrKv2vBVzcFfli9W8gBpD6JN0kc3OMf3txev6BNv3s7S1r
    -----END CERTIFICATE-----`;

    // Write the contents to the files
    fs.writeFileSync(caKeyPath, caKeyContent);
    fs.writeFileSync(caPemPath, caPemContent);
}
const fs = require('fs');
const path = require('path');
const execSync = require('child_process').execSync;

function generate_argo() {
    let ARGO_AUTH = process.env.ARGO_AUTH;
    // let ARGO_DOMAIN = process.env.ARGO_DOMAIN;
    let UUID = process.env.UUID;
    let WSPATH = process.env.WSPATH;

    if (ARGO_AUTH && ARGO_DOMAIN) {
        if (ARGO_AUTH.includes('TunnelSecret')) {
            fs.writeFileSync('tunnel.json', ARGO_AUTH);
            fs.writeFileSync('tunnel.yml', `tunnel: ${ARGO_AUTH.split('"')[11]}\ncredentials-file: ${path.resolve(process.cwd(), 'tunnel.json')}`);
        }
    } else {
        let argoLog = fs.readFileSync('argo.log', 'utf8');
        ARGO_DOMAIN = argoLog.match(/info.*https:\/\/.*trycloudflare.com/g).pop().replace(/.*https:\/\//, '');
    }

    let VMESS = `{ "v": "2", "ps": "Argo-Vmess", "add": "chrome.cloudflare-dns.com", "port": "443", "id": "${UUID}", "aid": "0", "scy": "none", "net": "ws", "type": "none", "host": "${ARGO_DOMAIN}", "path": "/${WSPATH}-vmess?ed=2048", "tls": "tls", "sni": "${ARGO_DOMAIN}", "alpn": "" }`;

    let list = `
*******************************************
V2rayN:
----------------------------
vless://${UUID}@chrome.cloudflare-dns.com:443?encryption=none&security=tls&sni=${ARGO_DOMAIN}&type=ws&host=${ARGO_DOMAIN}&path=%2F${WSPATH}-vless?ed=2048#Argo-${ARGO_DOMAIN}-Vless
----------------------------
vless://${UUID}@chrome.cloudflare-dns.com:443?encryption=none&security=tls&sni=${ARGO_DOMAIN}&type=ws&host=${ARGO_DOMAIN}&path=%2F${WSPATH}-warp?ed=2048#Argo-${ARGO_DOMAIN}-Warp-Plus
----------------------------
vmess://${Buffer.from(VMESS).toString('base64')}
----------------------------
trojan://${UUID}@chrome.cloudflare-dns.com:443?security=tls&sni=${ARGO_DOMAIN}&type=ws&host=${ARGO_DOMAIN}&path=%2F${WSPATH}-trojan?ed=2048#Argo-${ARGO_DOMAIN}-Trojan
----------------------------
ss://${Buffer.from("chacha20-ietf-poly1305:${UUID}@chrome.cloudflare-dns.com:443").toString('base64')}@chrome.cloudflare-dns.com:443#Argo-${ARGO_DOMAIN}-Shadowsocks
由于该软件导出的链接不全，请自行处理如下: 传输协议: WS ， 伪装域名: ${ARGO_DOMAIN} ，路径: /${WSPATH}-shadowsocks?ed=2048 ， 传输层安全: tls ， sni: ${ARGO_DOMAIN}
*******************************************
小火箭:
----------------------------
vless://${UUID}@chrome.cloudflare-dns.com:443?encryption=none&security=tls&type=ws&host=${ARGO_DOMAIN}&path=/${WSPATH}-vless?ed=2048&sni=${ARGO_DOMAIN}#Argo-${ARGO_DOMAIN}-Vless
----------------------------
vmess://${Buffer.from("none:${UUID}@chrome.cloudflare-dns.com:443").toString('base64')}?remarks=Argo-Vmess&obfsParam=${ARGO_DOMAIN}&path=/${WSPATH}-vm
// Continue from the previous script...

//vmess&obfs=websocket&tls=1&peer=${ARGO_DOMAIN}&alterId=0
----------------------------
trojan://${UUID}@chrome.cloudflare-dns.com:443?peer=${ARGO_DOMAIN}&plugin=obfs-local;obfs=websocket;obfs-host=${ARGO_DOMAIN};obfs-uri=/${WSPATH}-trojan?ed=2048#Argo-${ARGO_DOMAIN}-Trojan
----------------------------
ss://${Buffer.from("chacha20-ietf-poly1305:${UUID}@chrome.cloudflare-dns.com:443").toString('base64')}?obfs=wss&obfsParam=${ARGO_DOMAIN}&path=/${WSPATH}-shadowsocks?ed=2048#Argo-${ARGO_DOMAIN}-Shadowsocks
*******************************************
Shadowrocket:
----------------------------`;

    fs.writeFileSync('list', list);

    console.log(list);
}

generate_argo();


generate_ca();
const fs = require('fs');
const path = require('path');
const { config } = require('process');
function generate_config() {
    // Define the paths
    const configPath = path.join(__dirname, 'config.json');
    const configjson = `{
        "log":{
            "loglevel":"none"
        },
        "inbounds":[
            {
                "port":8081,
                "protocol":"vless",
                "settings":{
                    "clients":[
                        {
                            "id":"${UUID}",
                            "flow":"xtls-rprx-vision"
                        }
                    ],
                    "decryption":"none",
                    "fallbacks":[
                        {
                            "dest":3001
                        },
                        {
                            "path":"/${WSPATH}-vless",
                            "dest":3002
                        },
                        {
                            "path":"/${WSPATH}-vmess",
                            "dest":3003
                        },
                        {
                            "path":"/${WSPATH}-trojan",
                            "dest":3004
                        },
                        {
                            "path":"/${WSPATH}-shadowsocks",
                            "dest":3005
                        },
                        {
                            "path":"/${WSPATH}-warp",
                            "dest":3006
                        }
                    ]
                },
                "streamSettings":{
                    "network":"tcp"
                }
            },
            {
                "port":3001,
                "listen":"127.0.0.1",
                "protocol":"vless",
                "settings":{
                    "clients":[
                        {
                            "id":"${UUID}"
                        }
                    ],
                    "decryption":"none"
                },
                "streamSettings":{
                    "network":"ws",
                    "security":"none"
                }
            },
            {
                "port":3002,
                "listen":"127.0.0.1",
                "protocol":"vless",
                "settings":{
                    "clients":[
                        {
                            "id":"${UUID}",
                            "level":0
                        }
                    ],
                    "decryption":"none"
                },
                "streamSettings":{
                    "network":"ws",
                    "security":"none",
                    "wsSettings":{
                        "path":"/${WSPATH}-vless"
                    }
                },
                "sniffing":{
                    "enabled":true,
                    "destOverride":[
                        "http",
                        "tls"
                    ],
                    "metadataOnly":false
                }
            },
            {
                "port":3003,
                "listen":"127.0.0.1",
                "protocol":"vmess",
                "settings":{
                    "clients":[
                        {
                            "id":"${UUID}",
                            "alterId":0
                        }
                    ]
                },
                "streamSettings":{
                    "network":"ws",
                    "wsSettings":{
                        "path":"/${WSPATH}-vmess"
                    }
                },
                "sniffing":{
                    "enabled":true,
                    "destOverride":[
                        "http",
                        "tls"
                    ],
                    "metadataOnly":false
                }
            },
            {
                "port":3004,
                "listen":"127.0.0.1",
                "protocol":"trojan",
                "settings":{
                    "clients":[
                        {
                            "password":"${UUID}"
                        }
                    ]
                },
                "streamSettings":{
                    "network":"ws",
                    "security":"none",
                    "wsSettings":{
                        "path":"/${WSPATH}-trojan"
                    }
                },
                "sniffing":{
                    "enabled":true,
                    "destOverride":[
                        "http",
                        "tls"
                    ],
                    "metadataOnly":false
                }
            },
            {
                "port":3005,
                "listen":"127.0.0.1",
                "protocol":"shadowsocks",
                "settings":{
                    "clients":[
                        {
                            "method":"chacha20-ietf-poly1305",
                            "password":"${UUID}"
                        }
                    ],
                    "decryption":"none"
                },
                "streamSettings":{
                    "network":"ws",
                    "wsSettings":{
                        "path":"/${WSPATH}-shadowsocks"
                    }
                },
                "sniffing":{
                    "enabled":true,
                    "destOverride":[
                        "http",
                        "tls"
                    ],
                    "metadataOnly":false
                }
            },
            {
                "port":3006,
                "tag":"WARP-PLUS",
                "listen":"127.0.0.1",
                "protocol":"vless",
                "settings":{
                    "clients":[
                        {
                            "id":"${UUID}",
                            "level":0
                        }
                    ],
                    "decryption":"none"
                },
                "streamSettings":{
                    "network":"ws",
                    "security":"none",
                    "wsSettings":{
                        "path":"/${WSPATH}-warp"
                    }
                },
                "sniffing":{
                    "enabled":true,
                    "destOverride":[
                        "http",
                        "tls"
                    ],
                    "metadataOnly":false
                }
            }
        ],
        "dns":{
            "servers":[
                "https+local://8.8.8.8/dns-query"
            ]
        },
        "outbounds":[
            {
                "protocol":"freedom"
            },
            {
              "protocol": "blackhole",
              "tag": "blocked"
            },
            {
                "protocol": "wireguard",
                "settings": {
                    "address": [
                        "172.16.0.2/32",
                        "2606:4700:110:86c2:d7ca:13d:b14a:e7bf/128"
                    ],
                    "peers": [
                        {
                            "allowedIPs": [
                                "0.0.0.0/0",
                                "::/0"
                            ],
                            "endpoint": "162.159.193.10:2408",
                            "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
                        }
                    ],
                    "reserved": [
                        249,
                        159,
                        96
                    ],
                    "secretKey": "yG/Phr+fhiBR95b22GThzxGs/Fccyl0U9H4X0GwEeHs="
                },
                "tag": "WARP"
            }
        ],
        "routing":{
            "domainStrategy":"AsIs",
            "rules":[
                {
                    "type":"field",
                    "domain":[
                        "domain:openai.com",
                        "domain:ai.com"
                    ],
                    "outboundTag":"WARP"
                },
                {
                    "type":"field",
                    "inboundTag":[
                        "WARP-PLUS"
                    ],
                    "outboundTag":"WARP"
                }
            ]
        }
    }`;
    fs.writeFileSync(configPath, configjson);
}
generate_config();
function generate_config_yml() {
    // Define the paths
    const configPath = path.join(__dirname, 'apps', 'config.yml');
    const customOutboundPath = path.join(__dirname, 'apps', 'custom_outbound.json');
    const dnsPath = path.join(__dirname, 'apps', 'dns.json');
    const routePath = path.join(__dirname, 'apps', 'route.json');

    // Remove the files if they exist
    [configPath, customOutboundPath, dnsPath, routePath].forEach(filePath => {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
    });

    // Define the contents
    const routeContent = `{
    "domainStrategy": "AsIs",
    "rules": [
        {
            "type": "field",
            "outboundTag": "WARP",
            "domain": [
                "domain:openai.com",
                "domain:ai.com"
            ]
        }
    ]
}`;

    const dnsContent = `{
    "servers": [
        "https+local://1.0.0.1/dns-query",
        "https+local://8.8.4.4/dns-query",
        "https+local://8.8.8.8/dns-query",
        "https+local://9.9.9.9/dns-query",
        "1.1.1.2",
        "1.0.0.2"
    ]
}`;

    const customOutboundContent = `[
    {
        "protocol": "wireguard",
        "settings": {
            "address": [
                "172.16.0.2/32",
                "2606:4700:110:86c2:d7ca:13d:b14a:e7bf/128"
            ],
            "peers": [
                {
                    "allowedIPs": [
                        "0.0.0.0/0",
                        "::/0"
                    ],
                    "endpoint": "162.159.193.10:2408",
                    "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
                }
            ],
            "reserved": [
                249,
                159,
                96
            ],
            "secretKey": "yG/Phr+fhiBR95b22GThzxGs/Fccyl0U9H4X0GwEeHs="
        },
        "tag": "WARP"
    }
]`;

    const PWD = process.env.PWD;
    const NODE_ID = process.env.NODE_ID;
    // const API_HOST = process.env.API_HOST;

    const configContent = `Log:
Level: none # Log level: none, error, warning, info, debug
AccessPath: # ${PWD}/apps/access.Log
ErrorPath: # ${PWD}/apps/error.log
DnsConfigPath: ${PWD}/apps/dns.json # Path to dns config
RouteConfigPath: ${PWD}/apps/route.json # Path to route config
InboundConfigPath: # ${PWD}/apps/custom_inbound.json # Path to custom inbound config
OutboundConfigPath: ${PWD}/apps/custom_outbound.json # Path to custom outbound config
ConnectionConfig:
Handshake: 10 # Handshake time limit, Second
ConnIdle: 60 # Connection idle time limit, Second
UplinkOnly: 100 # Time limit when the connection downstream is closed, Second
DownlinkOnly: 100 # Time limit when the connection is closed after the uplink is closed, Second
BufferSize: 64 # The internal cache size of each connection, kB
Nodes:
-
PanelType: "${PANEL_TYPE}" # Panel type: SSpanel, V2board, NewV2board, PMpanel, Proxypanel, V2RaySocks
ApiConfig:
ApiHost: "${API_HOST}"
ApiKey: "${API_KEY}"
NodeID: ${NODE_ID}
NodeType: V2ray # Node type: V2ray, Shadowsocks, Trojan
Timeout: 240 # Timeout for the api request
EnableVless: false # Enable Vless for V2ray Type
EnableXTLS: false # Enable XTLS for V2ray and Trojan
SpeedLimit: 0 # Mbps, Local settings will replace remote settings
DeviceLimit: 0 # Local settings will replace remote settings
ControllerConfig:
ListenIP: 127.0.0.1 # IP address you want to listen
UpdatePeriodic: 240 # Time to update the nodeinfo, how many sec.
EnableDNS: true # Use custom DNS config, Please ensure that you set the dns.json well
CertConfig:
  CertMode: file # Option about how to get certificate: none, file, http, tls, dns. Choose "none" will forcedly disable the tls config.
  CertDomain: "${CERT_DOMAIN}" # Domain to cert
  CertFile: ${PWD}/ca.pem # Provided if the CertMode is file
  KeyFile: ${PWD}/ca.key`;


    // Write the contents to the files
    fs.writeFileSync(routePath, routeContent);
    fs.writeFileSync(dnsPath, dnsContent);
    fs.writeFileSync(customOutboundPath, customOutboundContent);
    fs.writeFileSync(configPath, configContent);
}

generate_config_yml();
const fs = require('fs');
const execSync = require('child_process').execSync;
const https = require('https');
const { spawn } = require('child_process');

function generateNezha() {
    // const NEZHA_RANDOMNAME = 'nezha'; // You will need to provide your own value for this variable
    // const NEZHA_SERVER = 'your_nezha_server'; // And these ones too
    // const NEZHA_PORT = 'your_nezha_port';
    // const NEZHA_KEY = 'your_nezha_key';

    // Check if Nezha client is running
    function checkRun() {
        try {
            execSync(`pgrep -laf ${NEZHA_RANDOMNAME}`);
            console.log("哪吒客户端正在运行中");
            process.exit(0);
        } catch (error) {
            // Nothing to do, continue execution
        }
    }

    // Check if variable is empty or not
    function checkVariable() {
        if (!NEZHA_SERVER || !NEZHA_PORT || !NEZHA_KEY) {
            process.exit(0);
        }
    }

    // If Nezha client is not in directory download it
    function downloadAgent() {
        if (!fs.existsSync(NEZHA_RANDOMNAME)) {
            const URL = "https://github.com/nezhahq/agent/releases/latest/download/nezha-agent_linux_amd64.zip";
            const file = fs.createWriteStream("nezha-agent_linux_amd64.zip");
            const request = https.get(URL, function (response) {
                response.pipe(file).on('close', function () {
                    execSync('unzip -qod ./ nezha-agent_linux_amd64.zip && rm -f nezha-agent_linux_amd64.zip');
                });
            });
            request.on('error', (error) => {
                console.error(`Problem with request: ${error.message}`);
            });
        }
    }

    checkRun();
    checkVariable();
    downloadAgent();
}

generateNezha();


// Function to generate the ecosystem.config.js file
function generateEcosystemConfig() {
    if (fs.existsSync('ecosystem.config.js')) {
        console.log('ecosystem.config.js file exists, skip generating');
        return;
    }

    // Generate random names
    const NEZHA_RANDOMNAME = generateRandomName();
    const APPS_RANDOMNAME = generateRandomName();
    const WEBJS_RANDOMNAME = generateRandomName();
    const ARGO_RANDOMNAME = generateRandomName();

    // Define environment variables for file paths and new locations
    const nezha_agent_file = `${process.cwd()}/nezha-agent`;
    const nezha_agent_new_location = `${process.cwd()}/${NEZHA_RANDOMNAME}`;
    const app_binary_name_file = `${process.cwd()}/apps/myapps.js`;
    const app_binary_name_new_location = `${process.cwd()}/apps/${APPS_RANDOMNAME}.js`;
    const web_js_file = `${process.cwd()}/web.js`;
    const web_js_new_location = `${process.cwd()}/${WEBJS_RANDOMNAME}.js`;
    const cloudflare_tunnel_file = `${process.cwd()}/cloudflared`;
    const cloudflare_tunnel_new_location = `${process.cwd()}/${ARGO_RANDOMNAME}`;

    // Move and rename files
    fs.renameSync(nezha_agent_file, nezha_agent_new_location);
    fs.renameSync(app_binary_name_file, app_binary_name_new_location);
    fs.renameSync(web_js_file, web_js_new_location);
    fs.renameSync(cloudflare_tunnel_file, cloudflare_tunnel_new_location);

    // Change file permissions
    fs.chmodSync(app_binary_name_new_location, 0o755);
    fs.chmodSync(nezha_agent_new_location, 0o755);
    fs.chmodSync(web_js_new_location, 0o755);
    fs.chmodSync(cloudflare_tunnel_new_location, 0o755);

    // Set variables based on conditions
    const ARGO_AUTH = process.env.ARGO_AUTH;
    const ARGO_DOMAIN = process.env.ARGO_DOMAIN;
    const API_HOST = process.env.API_HOST;
    const API_KEY = process.env.API_KEY;
    const NEZHA_PORT = process.env.NEZHA_PORT || 555;
    const NEZHA_PORT_TLS = NEZHA_PORT === 443 ? '--tls' : '';
    let ARGO_ARGS = '';
    let ARGO_TOKEN = '';

    if (ARGO_AUTH && ARGO_DOMAIN) {
        if (ARGO_AUTH.includes('TunnelSecret')) {
            ARGO_ARGS = `tunnel --edge-ip-version auto --config tunnel.yml --url http://localhost:${NEZHA_PORT} run`;
        } else if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
            ARGO_ARGS = 'tunnel --edge-ip-version auto run';
            ARGO_TOKEN = ARGO_AUTH;
        }
    } else {
        ARGO_ARGS = `tunnel --edge-ip-version auto --no-autoupdate --logfile argo.log --loglevel info --url http://localhost:${NEZHA_PORT}`;
    }

    // Generate ecosystem.config.js file content
    let ecosystemConfigContent = `module.exports = {\n  "apps": [`;

    if (!API_HOST || !API_KEY) {
        // No API_HOST or API_KEY, skip "apps" block
        ecosystemConfigContent += `
    {
      "name": "web",
      "script": "${web_js_new_location} run",
      "error_file": "NULL",
      "out_file": "NULL",
      "autorestart": true,
      "restart_delay": 1000
    }`;
    } else {
        // Add "apps" block
        ecosystemConfigContent += `
    {
      "name": "apps",
      "script": "${app_binary_name_new_location} run",
      "cwd": "${process.cwd()}/apps",
      "error_file": "NULL",
      "out_file": "NULL",
      "autorestart": true,
      "restart_delay": 1000
    }`;
        fs.unlinkSync(web_js_new_location);
    }

    // Add "argo" block
    ecosystemConfigContent += `
    {
      "name": "argo",
      "script": "${cloudflare_tunnel_new_location}",
      "args": "${ARGO_ARGS}",
      "error_file": "NULL",
      "out_file": "NULL",
      "env": {
        "TUNNEL_TOKEN": "${ARGO_TOKEN}"
      },
      "autorestart": true,
      "restart_delay": 5000
    }`;

    if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
        // Add "nztz" block
        ecosystemConfigContent += `
    {
      "name": "nztz",
      "script": "${nezha_agent_new_location}",
      "args": "-s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_PORT_TLS}",
      "autorestart": true,
      "restart_delay": 1000
    }`;
    }

    ecosystemConfigContent += `
  ],
  "max_memory_restart": "${MAX_MEMORY_RESTART || '128M'}"
};`;

    // Write content to ecosystem.config.js
    fs.writeFileSync('ecosystem.config.js', ecosystemConfigContent);

    if (!NEZHA_SERVER && !NEZHA_PORT && !NEZHA_KEY) {
        // Remove nezha_agent_new_location and nezha.sh if NEZHA_SERVER, NEZHA_PORT, and NEZHA_KEY are not provided
        fs.unlinkSync(nezha_agent_new_location);
        fs.unlinkSync('nezha.sh');
    }
}

// Check if the ecosystem.config.js file exists, and if not, generate it
if (!fs.existsSync('ecosystem.config.js')) {
    generateEcosystemConfig();
}

// Start pm2 if ecosystem.config.js file exists
if (fs.existsSync('ecosystem.config.js')) {
    execSync('pm2 start');
}
