const ws = new WebSocket(`ws://${location.host}`);
let sessionId = null;

// DOM refs
const tcpBtn = document.getElementById('tcpBtn');
const udpBtn = document.getElementById('udpBtn');
const printBtn = document.getElementById('printBtn');
const forwardBtn = document.getElementById('forwardBtn');
const disconnectTcpBtn = document.getElementById('disconnectTcpBtn');
const exportPcapBtn = document.getElementById('exportPcapBtn');
const targetIpInput = document.getElementById('targetIp');
const targetPortInput = document.getElementById('targetPort');
const setTargetBtn = document.getElementById('setTargetBtn');
const clearTargetBtn = document.getElementById('clearTargetBtn');
const targetStatus = document.getElementById('targetStatus');
const ipSpan = document.getElementById('ip');
const portSpan = document.getElementById('port');
const protoSpan = document.getElementById('currentProtocol');
const recvStream = document.getElementById('recvStream');
const sendStream = document.getElementById('sendStream');
const proxyStream = document.getElementById('proxyStream');
const echoToggle = document.getElementById('echoToggle');
const autoToggle = document.getElementById('autoToggle');
const autoContainer = document.getElementById('autoContainer');
const addAutoBtn = document.getElementById('addAuto');
const manualInput = document.getElementById('manualInput');
const sendManualBtn = document.getElementById('sendManual');
const formatRadios = document.querySelectorAll('input[name="format"]');

const switchProxy = document.getElementById('switchProxy');
const switchHTTP = document.getElementById('switchHTTP');
const switchCOAP = document.getElementById('switchCOAP');
const proxyView = document.getElementById('proxyView');
const httpView = document.getElementById('httpView');

const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const refreshFiles = document.getElementById('refreshFiles');
const fileList = document.getElementById('fileList');
const httpStream = document.getElementById('httpStream');
const exportPcapHttpBtn = document.getElementById('exportPcapHttpBtn');

let format = 'HEX';
let printing = { tcp: true, udp: true };
let forwarding = true;
let proto = 'tcp';

ipSpan.textContent = location.hostname;

const sendCtrl = obj => ws.send(JSON.stringify(obj));

function clearAll() {
    recvStream.innerHTML = '<h4>接收 (客户端→服务器)</h4>';
    sendStream.innerHTML = '<h4>发送 (服务器→客户端)</h4>';
    proxyStream.innerHTML = '<h4>代理 (服务器↔目标)</h4>';
    httpStream.innerHTML = '';
}

function updatePrintBtn() {
    printBtn.textContent = printing[proto] ? '暂停打印' : '开启打印';
}

function updateForwardBtn() {
    forwardBtn.textContent = forwarding ? '暂停转发' : '开启转发';
}

function updateDisconnectBtn() {
    disconnectTcpBtn.disabled = proto !== 'tcp';
}

function updateProtoBtns() {
    tcpBtn.classList.toggle('active', proto === 'tcp');
    udpBtn.classList.toggle('active', proto === 'udp');
    protoSpan.textContent = proto.toUpperCase();
}

function switchProto(p) {
    proto = p;
    clearAll();
    updateProtoBtns();
    updatePrintBtn();
    updateDisconnectBtn();
    sendCtrl({ type: 'setProtocol', value: p });
}

tcpBtn.onclick = () => switchProto('tcp');
udpBtn.onclick = () => switchProto('udp');

printBtn.onclick = () => {
    printing[proto] = !printing[proto];
    updatePrintBtn();
    sendCtrl({ type: 'setPrint', proto, value: printing[proto] });
};

forwardBtn.onclick = () => {
    forwarding = !forwarding;
    updateForwardBtn();
    sendCtrl({ type: 'setForward', value: forwarding });
};

disconnectTcpBtn.onclick = () => sendCtrl({ type: 'disconnectTCP' });
exportPcapBtn.onclick = () => {
    if (!sessionId) return alert('未获取会话ID');
    window.location.href = `/export.pcap?sid=${sessionId}`;
};
exportPcapHttpBtn.onclick = exportPcapBtn.onclick;

setTargetBtn.onclick = () => {
    const ip = targetIpInput.value.trim();
    const port = parseInt(targetPortInput.value, 10);
    if (!ip || isNaN(port)) return alert('请输入合法 IP 和端口');
    sendCtrl({ type: 'setTarget', ip, port });
};

clearTargetBtn.onclick = () => sendCtrl({ type: 'setTarget', ip: null, port: null });

formatRadios.forEach(r => r.onchange = () => format = r.value);

echoToggle.onchange = () => {
    if (echoToggle.checked) {
        autoToggle.checked = false;
        sendCtrl({ type: 'setAuto', value: false });
    }
    sendCtrl({ type: 'setEcho', value: echoToggle.checked });
};

autoToggle.onchange = () => {
    if (autoToggle.checked) {
        echoToggle.checked = false;
        sendCtrl({ type: 'setEcho', value: false });
        updateAutoMsgs();
    }
    sendCtrl({ type: 'setAuto', value: autoToggle.checked });
};

function updateAutoMsgs() {
    const msgs = Array.from(autoContainer.querySelectorAll('.autoMsg'))
        .map(i => i.value.trim())
        .filter(v => v);
    if (msgs.some(v => !/^[0-9A-Fa-f]+$/.test(v) || v.length % 2 !== 0)) return alert('HEX 格式错误');
    sendCtrl({ type: 'setAutoMsgs', msgs });
}

addAutoBtn.onclick = () => {
    const row = document.createElement('div');
    row.className = 'autoMsgRow';
    row.innerHTML = `<input class="autoMsg" placeholder="循环响应(HEX)">`;
    autoContainer.appendChild(row);
};

autoContainer.addEventListener('change', updateAutoMsgs);

sendManualBtn.onclick = () => {
    const v = manualInput.value.trim();
    if (!v) return;
    let buf;
    if (format === 'HEX') {
        const h = v.replace(/\s+/g, '');
        if (!/^[0-9A-Fa-f]+$/.test(h) || h.length % 2 !== 0) return alert('HEX 格式错误');
        buf = new Uint8Array(h.match(/.{1,2}/g).map(h => parseInt(h, 16)));
    } else {
        buf = new TextEncoder().encode(v);
    }
    ws.send(buf);
    manualInput.value = '';
};

function render(type, data, ts, evt) {
    const t = new Date(ts).toLocaleTimeString();
    let cont, html;
    switch (type) {
        case 'tcpData': cont = recvStream; break;
        case 'serverData': cont = sendStream; break;
        case 'proxySend':
        case 'proxyRecv': cont = proxyStream; break;
        case 'system':
            html = `<span class="timestamp">${t}</span><span>${evt === 'tcpConnect' ? '✅ 已连接' : '❌ 已断开'}</span>`;
            break;
        case 'session':
            return;
        case 'targetStatus':
            targetStatus.textContent = data || evt;
            return;
        case 'httpLog':
            renderHTTPLog(data);
            return;
        default:
            return;
    }
    if (type === 'system') {
        html = `<span class="timestamp">${t}</span><span>${evt === 'tcpConnect' ? '✅ 已连接' : '❌ 已断开'}</span>`;
    } else {
        let disp = data;
        if (format === 'ASCII') {
            disp = new TextDecoder().decode(new Uint8Array(
                data.split(' ').map(h => parseInt(h, 16))
            ));
        }
        let lbl;
        if (type === 'proxySend') lbl = `服→目${format}`;
        else if (type === 'proxyRecv') lbl = `目→服${format}`;
        else if (type === 'tcpData') lbl = `接收${format}`;
        else lbl = `发送${format}`;
        html = [
            `<span class="label">${lbl}</span>`,
            `<span class="timestamp">${t}</span>`,
            `<div>${disp}</div>`
        ].join('');
    }
    const e = document.createElement('div');
    e.className = 'entry';
    e.innerHTML = html;
    cont.appendChild(e);
    cont.scrollTop = cont.scrollHeight;
}

// 切换视图
function switchView(view) {
    proxyView.classList.toggle('active', view === 'proxy');
    httpView.classList.toggle('active', view === 'http');
    switchProxy.classList.toggle('active', view === 'proxy');
    switchHTTP.classList.toggle('active', view === 'http');
}

switchProxy.onclick = () => switchView('proxy');
switchHTTP.onclick = () => switchView('http');

// 新增：跳转到COAP页面
switchCOAP.onclick = () => {
    window.location.href = '/coap.html';
};

// HTTP 文件上传
uploadBtn.onclick = () => {
    const file = fileInput.files[0];
    const folder = document.getElementById('folderPath').value.trim();
    if (!file) return alert('请选择文件');
    if (file.size > 2 * 1024 * 1024) return alert('文件不能超过2MB');

    const formData = new FormData();
    formData.append('file', file);
    formData.append('folder', folder);

    fetch('/upload', { method: 'POST', body: formData })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                refreshFileList();
                fileInput.value = '';
                document.getElementById('folderPath').value = '';
            }
        });
};

// 修改文件列表刷新函数
function refreshFileList() {
    fetch('/api/files')
        .then(res => res.json())
        .then(files => {
			fileList.innerHTML = files.map(f => `
			  <div class="file-item">
				<span>${f.path.replace(/\\/g, '/')} (${(f.size / 1024).toFixed(1)}KB)</span>
				<button class="copy-url" data-path="${f.path}">复制URL</button>
				<button class="delete-file" data-path="${f.path}">删除</button>
			  </div>
			`).join('');
            
            // 添加复制功能
			document.querySelectorAll('.copy-url').forEach(btn => {
				btn.onclick = () => {
					const path = btn.dataset.path.replace(/\\/g, '/');
					const url = `http://${location.host}/uploads/${path}`;

					// 方案1: 优先使用剪贴板API
					if (navigator.clipboard) {
						navigator.clipboard.writeText(url)
							.then(() => alert('URL已复制'))
							.catch(() => copyWithFallback(url));
					} else {
						// 方案2: 降级到execCommand
						copyWithFallback(url);
					}
				};
			});
			document.querySelectorAll('.delete-file').forEach(btn => {
				btn.onclick = () => {
					const path = btn.dataset.path;
					if (confirm('确定要删除此文件吗？')) {
						fetch('/api/files', {
							method: 'DELETE',
							headers: { 'Content-Type': 'application/json' },
							body: JSON.stringify({ path })
						}).then(res => res.ok && refreshFileList());
					}
				};
			});
        });
}
refreshFiles.onclick = refreshFileList;

function renderHTTPLog(entry) {
    const html = `
        <div class="http-entry">
            <div class="http-request">
                <span class="timestamp">${new Date(entry.timestamp).toLocaleTimeString()}</span>
                <span class="label">${entry.method}</span>
                <span>${entry.path}</span>
            </div>
            <div class="http-response">
                <span class="label">${entry.status}</span>
                <span>(${entry.duration}ms)</span>
            </div>
        </div>
    `;
    httpStream.innerHTML += html;
    httpStream.scrollTop = httpStream.scrollHeight;
}

ws.onmessage = evt => {
    const m = JSON.parse(evt.data);
    switch (m.type) {
        case 'session':
            sessionId = m.sessionId;
            break;
        case 'portAssigned':
            portSpan.textContent = m.port;
            protoSpan.textContent = m.protocol.toUpperCase();
            break;
        case 'tcpData':
        case 'serverData':
        case 'proxySend':
        case 'proxyRecv':
        case 'system':
        case 'targetStatus':
            render(m.type, m.data, m.timestamp, m.event);
            break;
        case 'httpLog':
            renderHTTPLog(m.data);
            break;
    }
};

ws.onopen = () => {
    updatePrintBtn();
    updateForwardBtn();
    switchProto('tcp');
    refreshFileList();
};
