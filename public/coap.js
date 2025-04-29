let sessionID = '', udpPort = 0;
let recMsgs = [], sentMsgs = [], recvCnt = 0;

// 初始化 Session
async function initSession() {
  const res = await fetch('/api/session');
  const j = await res.json();
  sessionID = j.sessionID;
  udpPort = j.port;
  document.getElementById('udp-port').innerText = udpPort;
  document.getElementById('session-id').innerText = sessionID;
}
initSession();

// 定时更新客户端列表
setInterval(async () => {
  if (!sessionID) return;
  const res = await fetch(`/api/clients/${sessionID}`);
  const list = await res.json();
  const sel = document.getElementById('client-select');
  const prev = sel.value;
  sel.innerHTML = `<option value="">手动输入</option>`;
  list.forEach(c => {
    const o = document.createElement('option');
    o.value = c.id;
    o.innerText = c.id;
    if (c.id === prev) o.selected = true;
    sel.appendChild(o);
  });
}, 1000);

// 渲染收到和发送的报文
function render() {
  ['received-box', 'sent-box'].forEach(id => {
    const box = document.getElementById(id);
    const arr = id === 'received-box' ? recMsgs : sentMsgs;
    box.innerHTML = '';
    arr.forEach((m, i) => {
      const d = document.createElement('div');
      d.className = 'message-item';
      d.innerText = `#${i + 1}\n${m}`;
      box.appendChild(d);
    });
  });
}

// 拉取最新报文并自动循环响应
setInterval(async () => {
  if (!sessionID) return;
  const res = await fetch(`/api/last-packet/${sessionID}`);
  const pkt = await res.json();
  const txt = JSON.stringify(pkt, null, 2);
  if (!recMsgs.length || recMsgs.at(-1) !== txt) {
    recMsgs.push(txt);
    recvCnt++;
    if (document.getElementById('loop-response').checked) {
      sendRow(recvCnt - 1);
    }
    render();
  }
}, 500);

// 添加/删除自定义字段行
function addRow(d = {}) {
  const tbody = document.getElementById('rows-tbody');
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td><input class="short" value="${d.code || '0.00'}"></td>
    <td><input class="short" placeholder="自动" value="${d.messageId || ''}"></td>
    <td><input class="medium" value="${d.token || ''}"></td>
    <td><textarea class="long" rows="2">${d.options ? JSON.stringify(d.options) : '[]'}</textarea></td>
    <td><textarea class="long" rows="3">${d.payload || ''}</textarea></td>
    <td><button class="btn remove">删除</button></td>
  `;
  tr.querySelector('.remove').onclick = () => tr.remove();
  tbody.appendChild(tr);
}
document.getElementById('add-row').onclick = () => addRow();
addRow(); // 初始一行

// 发送指定行 CoAP 报文
async function sendRow(idx) {
  const rows = Array.from(document.querySelectorAll('#rows-tbody tr'));
  if (!rows[idx]) return;
  const [c, id, t, o, p] = rows[idx].querySelectorAll('input, textarea');
  let opts = [];
  try { opts = JSON.parse(o.value); } catch {}
  const body = {
    targetIP: (() => {
      const v = document.getElementById('client-select').value;
      return v ? v.split(':')[0] : document.getElementById('ip').value;
    })(),
    targetPort: (() => {
      const v = document.getElementById('client-select').value;
      if (v) return +v.split(':')[1];
      const pp = +document.getElementById('port').value;
      return isNaN(pp) ? udpPort : pp;
    })(),
    code: c.value || '0.00',
    messageId: parseInt(id.value) || undefined,
    token: t.value,
    options: opts,
    payload: p.value
  };
  await fetch(`/api/send/${sessionID}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  sentMsgs.push(JSON.stringify(body, null, 2));
  render();
}

// 手动发送第1行
document.getElementById('send-btn').onclick = () => sendRow(0);

// 保存报文到JSON
document.getElementById('save-btn').onclick = () => {
  const arr = Array.from(document.querySelectorAll('#rows-tbody tr')).map(tr => {
    const [c, id, t, o, p] = tr.querySelectorAll('input, textarea');
    let opts = [];
    try { opts = JSON.parse(o.value); } catch {}
    return {
      code: c.value,
      messageId: id.value || undefined,
      token: t.value,
      options: opts,
      payload: p.value
    };
  });
  const blob = new Blob([JSON.stringify(arr, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob), a = document.createElement('a');
  a.href = url;
  a.download = `coap_${sessionID}.json`;
  a.click();
  URL.revokeObjectURL(url);
};

// 读取报文 JSON 文件
const fi = document.getElementById('file-input');
document.getElementById('load-btn').onclick = () => fi.click();
fi.onchange = e => {
  const f = e.target.files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const arr = JSON.parse(reader.result);
      if (!Array.isArray(arr)) throw '';
      document.getElementById('rows-tbody').innerHTML = '';
      arr.forEach(item => addRow(item));
    } catch {
      alert('读取失败：JSON 格式错误');
    }
  };
  reader.readAsText(f);
};

// 导出当前 Session 的 PCAP 文件
document.getElementById('export-pcap-btn').onclick = () => {
  window.location.href = `/api/export-pcap/${sessionID}`;
};
