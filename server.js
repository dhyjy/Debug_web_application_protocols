// server.js
const express = require('express');
const http = require('http');
const net = require('net');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const multer = require('multer');
const coapPacket = require('coap-packet'); // 新增

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const UPLOAD_DIR = 'uploads';
const PCAP_DIR = 'pcaps';
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
if (!fs.existsSync(PCAP_DIR)) fs.mkdirSync(PCAP_DIR);

const DUMPCAP_BIN = process.env.DUMPCAP_PATH || 'dumpcap';
const DUMPCAP_IFACE = process.env.DUMPCAP_IFACE || 'any'; // 修改默认any接口

const sessions = new Map();
const coapSessions = new Map(); // 新增CoAP sessions

// 上传
// 修改multer存储配置
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        try {
            const folder = req.body.folder || '';
            const destPath = path.join(UPLOAD_DIR, folder);
            
            // 防止路径遍历攻击
            const resolvedPath = path.resolve(destPath);
            if (!resolvedPath.startsWith(path.resolve(UPLOAD_DIR))) {
                return cb(new Error('非法路径'));
            }
            
            fs.mkdirSync(resolvedPath, { recursive: true });
            cb(null, resolvedPath);
        } catch (err) {
            cb(err);
        }
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 } });

// 中间件
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

// WebSocket
wss.on('connection', ws => {
  const sessionId = crypto.randomBytes(8).toString('hex');
  const captureFile = path.join(__dirname, `capture-${sessionId}.pcap`);
  const startDumpcap = makeStarter(captureFile, sessionId);

  sessions.set(sessionId, { captureFile, dumpcapProc: null });

  let protocol = 'tcp';
  let echoMode = false;
  let autoMode = false;
  let autoMsgs = [];
  let autoIndex = 0;
  let printing = { tcp: true, udp: true };
  let forwarding = true;
  let tcpServer, tcpSocket;
  let udpServer, udpClientRinfo;
  let targetIp, targetPort, targetTcpSock, udpProxySock;

  const sendJSON = o => ws.send(JSON.stringify(o));
  const log = (type, data, event) => {
    if (!printing[protocol]) return;
    sendJSON({ type, data, timestamp: Date.now(), event });
  };
  const logSys = evt => {
    if (protocol === 'tcp' && !printing.tcp) return;
    sendJSON({ type: 'system', event: evt, timestamp: Date.now() });
  };

  function makeStarter(captureFile, sessionId) {
    let proc = null;
    return function startDumpcap(filter) {
      if (proc) proc.kill();
      try { fs.unlinkSync(captureFile); } catch {}
      const args = ['-i', DUMPCAP_IFACE, '-f', filter, '-w', captureFile];
      proc = spawn(DUMPCAP_BIN, args);
      proc.on('error', err => console.error(`dumpcap(${sessionId}) error:`, err));
      console.log(`🔍 [${sessionId}] 抓包启动 iface=${DUMPCAP_IFACE} filter="${filter}"`);
      const s = sessions.get(sessionId);
      if (s) s.dumpcapProc = proc;
    };
  }

  function updateCapture(port) {
    const filter = `(tcp port ${port} or udp port ${port}) and not src host ::1 and not dst host ::1`;
    startDumpcap(filter);
  }

  function startTCP() {
    tcpServer = net.createServer(sock => {
      tcpSocket = sock;
      logSys('tcpConnect');
      sock.on('data', buf => {
        const hex = buf.toString('hex').match(/.{1,2}/g).join(' ');
        log('tcpData', hex);
        if (echoMode) { sock.write(buf); log('serverData', hex, 'send'); }
        if (autoMode) {
          const m = autoMsgs[autoIndex]; autoIndex = (autoIndex + 1) % autoMsgs.length;
          sock.write(m);
          log('serverData', m.toString('hex').match(/.{1,2}/g).join(' '), 'send');
        }
        if (forwarding && targetIp && targetPort && targetTcpSock) {
          targetTcpSock.write(buf);
          log('proxySend', hex);
        }
      });
      sock.on('end', () => logSys('tcpDisconnect'));
    }).listen(0, () => {
      const port = tcpServer.address().port;
      sendJSON({ type: 'portAssigned', port, protocol });
      updateCapture(port);
    });
  }

  function startUDP() {
    udpServer = dgram.createSocket('udp4');
    udpServer.on('message', (msg, rinfo) => {
      const hex = msg.toString('hex').match(/.{1,2}/g).join(' ');
      log('tcpData', hex);
      if (echoMode) {
        udpServer.send(msg, rinfo.port, rinfo.address);
        log('serverData', hex, 'send');
      }
      if (autoMode) {
        const m = autoMsgs[autoIndex]; autoIndex = (autoIndex + 1) % autoMsgs.length;
        udpServer.send(m, rinfo.port, rinfo.address);
        log('serverData', m.toString('hex').match(/.{1,2}/g).join(' '), 'send');
      }
      if (forwarding && targetIp && targetPort && udpProxySock) {
        udpProxySock.send(msg, targetPort, targetIp);
        log('proxySend', hex);
      }
      udpClientRinfo = rinfo;
    });
    udpServer.bind(0, () => {
      const port = udpServer.address().port;
      sendJSON({ type: 'portAssigned', port, protocol });
      updateCapture(port);
    });
  }

  function connectTarget(ip, port) {
    targetTcpSock?.destroy();
    udpProxySock?.close();
    targetIp = ip; targetPort = port;
    if (protocol === 'tcp') {
      targetTcpSock = net.connect(port, ip, () => sendJSON({ type: 'targetStatus', status: 'connected' }));
      targetTcpSock.on('data', buf => {
        const hex = buf.toString('hex').match(/.{1,2}/g).join(' ');
        log('proxyRecv', hex);
        tcpSocket?.write(buf);
      });
      targetTcpSock.on('close', () => sendJSON({ type: 'targetStatus', status: 'disconnected' }));
    } else {
      udpProxySock = dgram.createSocket('udp4');
      udpProxySock.bind(0, () => sendJSON({ type: 'targetStatus', status: 'ready' }));
      udpProxySock.on('message', msg => {
        const hex = msg.toString('hex').match(/.{1,2}/g).join(' ');
        log('proxyRecv', hex);
        udpClientRinfo && udpServer.send(msg, udpClientRinfo.port, udpClientRinfo.address);
      });
    }
  }

  startTCP();
  sendJSON({ type: 'session', sessionId });

  ws.on('message', (msg, isBinary) => {
    if (isBinary) {
      if (protocol === 'tcp' && tcpSocket) tcpSocket.write(msg);
      else if (protocol === 'udp' && udpClientRinfo) {
        udpServer.send(msg, udpClientRinfo.port, udpClientRinfo.address);
      }
      log('serverData', msg.toString('hex').match(/.{1,2}/g).join(' '));
      return;
    }

    try {
      const o = JSON.parse(msg);
      switch (o.type) {
        case 'setProtocol':
          protocol === 'tcp' ? tcpServer.close() : udpServer.close();
          protocol = o.value;
          protocol === 'tcp' ? startTCP() : startUDP();
          break;
        case 'setEcho':
          echoMode = o.value;
          if (o.value) autoMode = false;
          break;
        case 'setAuto':
          autoMode = o.value;
          if (o.value) echoMode = false;
          break;
        case 'setAutoMsgs':
          autoMsgs = o.msgs.map(s => Buffer.from(s.replace(/\s+/g, ''), 'hex'));
          autoIndex = 0;
          break;
        case 'setPrint': printing[o.proto] = o.value; break;
        case 'setForward': forwarding = o.value; break;
        case 'disconnectTCP': tcpSocket?.end(); break;
        case 'setTarget':
          o.ip && o.port ? connectTarget(o.ip, o.port) : (targetIp = targetPort = null);
          break;
      }
    } catch (e) {
      console.error('消息解析失败:', e);
    }
  });

  ws.on('close', () => {
    tcpServer?.close();
    udpServer?.close();
    sessions.get(sessionId)?.dumpcapProc?.kill();
    sessions.delete(sessionId);
  });
});
// ========== HTTP 文件服务相关 ==========
// HTTP日志中间件
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const entry = {
            timestamp: Date.now(),
            method: req.method,
            path: req.path,
            status: res.statusCode,
            duration: Date.now() - start
        };

        // 广播给所有客户端
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: 'httpLog',
                    data: entry
                }));
            }
        });
    });
    next();
});
// 文件上传接口
// 文件上传接口
app.post('/upload', upload.single('file'), (req, res) => {
    try {
        const folder = req.body.folder || ''; // 现在可以正确获取路径参数
        const finalDir = path.join(UPLOAD_DIR, folder);
        const finalPath = path.join(finalDir, req.file.originalname);
        
        // 路径安全检查
        if (!path.resolve(finalDir).startsWith(path.resolve(UPLOAD_DIR))) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: '非法路径' });
        }
        
        // 创建目标目录并移动文件
        fs.mkdirSync(finalDir, { recursive: true });
        fs.renameSync(req.file.path, finalPath);
        
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        fs.unlinkSync(req.file.path);
        res.status(500).json({ error: '文件移动失败' });
    }
});

// 刷新文件列表
app.get('/api/files', (req, res) => {
  const listFiles = dir => {
    const results = [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const item of entries) {
      const fullPath = path.join(dir, item.name);
      if (item.isDirectory()) {
        results.push(...listFiles(fullPath));
      } else {
        results.push({
          path: path.relative(UPLOAD_DIR, fullPath),
          name: item.name,
          size: fs.statSync(fullPath).size,
          uploaded: fs.statSync(fullPath).birthtime
        });
      }
    }
    return results;
  };
  try {
    const files = listFiles(UPLOAD_DIR);
    res.json(files);
  } catch {
    res.status(500).json({ error: '读取失败' });
  }
});

// 删除文件接口
app.delete('/api/files', express.json(), (req, res) => {
  const filePath = req.body.path;
  const fullPath = path.join(UPLOAD_DIR, filePath);
  if (!path.resolve(fullPath).startsWith(path.resolve(UPLOAD_DIR))) {
    return res.status(403).json({ error: '非法路径' });
  }
  fs.unlink(fullPath, err => {
    if (err) return res.status(500).json({ error: '删除失败' });
    res.json({ success: true });
  });
});

// ========== TCP/UDP PCAP导出 ==========
app.get('/export.pcap', (req, res) => {
  const sid = req.query.sid;
  if (!sid || !sessions.has(sid)) {
    return res.status(404).send('Invalid session');
  }
  const { captureFile } = sessions.get(sid);
  if (!fs.existsSync(captureFile)) {
    return res.status(404).send('No capture file');
  }
  res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
  res.setHeader('Content-Disposition', 'attachment; filename="capture.pcap"');
  fs.createReadStream(captureFile).pipe(res);
});

// ========== 新增 CoAP Server ==========

function randomPort(min = 60000, max = 65000) {
  return Math.floor(Math.random() * (max - min)) + min;
}

function createCoapSession() {
  const sessionID = crypto.randomBytes(8).toString('hex');
  const port = randomPort();
  const socket = dgram.createSocket('udp4');
  const clients = new Map();
  let lastPacket = null;

  socket.on('message', (msg, rinfo) => {
    const clientID = `${rinfo.address}:${rinfo.port}`;
    if (!clients.has(clientID)) {
      clients.set(clientID, { ip: rinfo.address, port: rinfo.port });
    }
    try {
      const pkt = coapPacket.parse(msg);
      lastPacket = {
        clientID,
        raw: msg.toString('hex'),
        parsed: {
          code: pkt.code,
          messageId: pkt.messageId,
          token: pkt.token.toString('hex'),
          options: pkt.options,
          payload: pkt.payload.toString()
        }
      };
    } catch {
      lastPacket = {
        clientID,
        raw: msg.toString('hex'),
        parsed: { error: 'Invalid CoAP format', payload: msg.toString() }
      };
    }
  });
  socket.bind(port);

  const filename = `coap_${sessionID}.pcap`;
  const filepath = path.join(PCAP_DIR, filename);
  const dumpcapProc = spawn(DUMPCAP_BIN, ['-i', DUMPCAP_IFACE, '-f', `udp port ${port}`, '-w', filepath, '-q']);
  dumpcapProc.on('error', err => {
    console.error(`dumpcap error for coap session ${sessionID}:`, err);
  });

  return {
    sessionID,
    port,
    socket,
    clients,
    lastPacketRef: () => lastPacket,
    pcap: { proc: dumpcapProc, filepath, filename }
  };
}

// CoAP APIs
app.get('/api/session', (req, res) => {
  const sess = createCoapSession();
  coapSessions.set(sess.sessionID, sess);
  res.json({ sessionID: sess.sessionID, port: sess.port });
});

app.get('/api/clients/:sessionID', (req, res) => {
  const s = coapSessions.get(req.params.sessionID);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  res.json([...s.clients.entries()].map(([id, { ip, port }]) => ({ id, ip, port })));
});

app.get('/api/last-packet/:sessionID', (req, res) => {
  const s = coapSessions.get(req.params.sessionID);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  res.json(s.lastPacketRef());
});

app.post('/api/send/:sessionID', (req, res) => {
  const s = coapSessions.get(req.params.sessionID);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  
  const { targetIP, targetPort, code, messageId, token, options, payload } = req.body;
  const packet = {
    code: code || '0.00',
    messageId: messageId || Math.floor(Math.random() * 65535),
    token: token ? Buffer.from(token, 'hex') : Buffer.alloc(0),
    options: options || [],
    payload: Buffer.from(payload || '')
  };
  
  try {
    const buf = coapPacket.generate(packet);
    s.socket.send(buf, targetPort, targetIP, err => {
      if (err) return res.status(500).json({ error: 'Failed to send packet' });
      res.json({ success: true });
    });
  } catch (err) {
    res.status(400).json({ error: 'Invalid CoAP packet format' });
  }
});

app.get('/api/export-pcap/:sessionID', (req, res) => {
  const sessionID = req.params.sessionID;
  const session = coapSessions.get(sessionID);
  
  if (!session) return res.status(404).json({ error: 'Session not found' });
  if (!fs.existsSync(session.pcap.filepath)) {
    return res.status(404).json({ error: 'PCAP file not found' });
  }
  res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
  res.setHeader('Content-Disposition', `attachment; filename="${session.pcap.filename}"`);
  const stream = fs.createReadStream(session.pcap.filepath);
  stream.pipe(res);
});

// 优雅关闭
process.on('SIGINT', () => {
  console.log('Closing all sessions...');
  sessions.forEach(s => s.dumpcapProc?.kill());
  coapSessions.forEach(s => { s.socket.close(); s.pcap.proc.kill(); });
  process.exit();
});

// 启动
server.listen(8080, () => {
  console.log('🚀 服务运行在 http://localhost:8080');
});
