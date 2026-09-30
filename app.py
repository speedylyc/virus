# -*- coding: utf-8 -*-
"""
服务器病毒扫描管理系统 - B/S架构版
功能：指定服务器扫描 + 历史记录 + 白名单 + 定时扫描 + 企业微信推送 + 目标机ClamAV管理
"""
import os, re, json, time, threading, requests, paramiko, shlex
from datetime import datetime
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, 'servers_config.json')
HISTORY_FILE = os.path.join(BASE_DIR, 'scan_history.json')
WHITELIST_FILE = os.path.join(BASE_DIR, 'whitelist.json')

state = {
    'servers_config': {}, 'scan_reports': {}, 'all_virus_files': [],
    'tasks': {}, 'clamav_info': {}, 'whitelist': [],
    'scan_stop': False, 'current_scan_task': None,
    'schedule': {'enabled':False,'cron':'0 9 * * 1','schedule_servers':[],'webhook':'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=7e116515-d60f-42cd-8d9d-6c0bd608def4'}
}


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE,'r',encoding='utf-8') as f: data = json.load(f)
            if 'servers' in data: state['servers_config'] = data['servers']
            if 'schedule' in data: state['schedule'].update(data['schedule'])
            print(f"[配置] 已加载 {len(state['servers_config'])} 台")
        except Exception as e: print(f"[配置] 加载失败: {e}")

def save_config():
    with open(CONFIG_FILE,'w',encoding='utf-8') as f:
        json.dump({'servers':state['servers_config'],'schedule':state['schedule']}, f, indent=2, ensure_ascii=False)

def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE,'r',encoding='utf-8') as f: state['whitelist'] = json.load(f)
        except: pass

def save_whitelist():
    with open(WHITELIST_FILE,'w',encoding='utf-8') as f: json.dump(state['whitelist'], f, indent=2, ensure_ascii=False)

def load_history():
    if not os.path.exists(HISTORY_FILE): return []
    try:
        with open(HISTORY_FILE,'r',encoding='utf-8') as f: return json.load(f)
    except: return []

def save_history(records):
    with open(HISTORY_FILE,'w',encoding='utf-8') as f: json.dump(records, f, indent=2, ensure_ascii=False)

def is_whitelisted(fp, vn):
    for it in state['whitelist']:
        if it.get('type')=='path' and it.get('pattern') in fp: return True
        if it.get('type')=='virus_name' and it.get('pattern') in vn: return True
    return False

def send_wechat_webhook(content, url=None):
    u = url or state['schedule'].get('webhook','')
    if not u: return
    try:
        r = requests.post(u, json={"msgtype":"text","text":{"content":content}}, timeout=10)
        print(f"[webhook] {r.status_code}")
    except Exception as e: print(f"[webhook] 失败: {e}")

def create_ssh(server_name):
    info = state['servers_config'].get(server_name)
    if not info: return None, f"服务器 {server_name} 配置不存在"
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kw = dict(hostname=info['ip'], port=info.get('port',22), username=info.get('user','root'), timeout=30)
        # 关键：指定hostkey算法，兼容新sshd和老paramiko
        if info.get('key_path') and os.path.exists(info['key_path']):
            kw['pkey'] = paramiko.RSAKey.from_private_key_file(info['key_path'])
        elif info.get('password'):
            kw['password'] = info['password']
        else:
            return None, "未配置认证"
        ssh.connect(**kw)
        return ssh, None
    except Exception as e:
        return None, str(e)

def create_ssh_direct(ip, port, user, password=None, key_path=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kw = dict(hostname=ip, port=port, username=user, timeout=30)
        if key_path and os.path.exists(key_path):
            kw['pkey'] = paramiko.RSAKey.from_private_key_file(key_path)
        else:
            kw['password'] = password
        ssh.connect(**kw)
        return ssh, None
    except Exception as e:
        return None, str(e)

def get_clamav_paths(server_name=None):
    """获取指定服务器的clamav路径配置，未配置则用默认值（老服务器源码编译路径）"""
    defaults = {
        'clamscan_path': '/opt/clamav/bin/clamscan',
        'freshclam_path': '/opt/clamav/bin/freshclam',
        'report_dir': '/home/clamscan',
        'db_dir': '/var/lib/clamav',
    }
    if server_name and server_name in state['servers_config']:
        info = state['servers_config'][server_name]
        for k in defaults:
            if info.get(k):
                defaults[k] = info[k]
    return defaults


def new_task(name):
    tid = f"task_{int(time.time()*1000)}"
    state['tasks'][tid] = {'name':name,'status':'running','progress':0,'total':100,'logs':[],'result':None,'start_time':datetime.now().isoformat()}
    return tid

def add_log(tid, msg, level='info'):
    if tid in state['tasks']:
        ts = datetime.now().strftime("%H:%M:%S")
        state['tasks'][tid]['logs'].append({'time':ts,'message':msg,'level':level})

def update_progress(tid, progress=None, total=None, status=None):
    if tid in state['tasks']:
        if progress is not None: state['tasks'][tid]['progress'] = progress
        if total is not None: state['tasks'][tid]['total'] = total
        if status is not None: state['tasks'][tid]['status'] = status

def finish_task(tid, result=None):
    if tid in state['tasks']:
        state['tasks'][tid]['status'] = 'finished'
        state['tasks'][tid]['result'] = result

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/config/servers', methods=['GET'])
def get_servers():
    servers = []
    for name, info in sorted(state['servers_config'].items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
        auth = '密钥' if info.get('key_path') else ('密码' if info.get('password') else '未配置')
        servers.append({'name':name,'ip':info.get('ip',''),'user':info.get('user','root'),'port':info.get('port',22),
                        'auth_type':auth,'connectivity':info.get('connectivity','未测试'),
                        'scan_paths':info.get('scan_paths',[])})
    return jsonify({'servers':servers})

@app.route('/api/config/server/scan-paths', methods=['POST'])
def update_scan_paths():
    d = request.json or {}
    name = d.get('server','')
    paths = d.get('paths',[])
    if name not in state['servers_config']:
        return jsonify({'success':False,'message':f'服务器 {name} 不存在'}),404
    # 清洗：去空、去重、保序
    cleaned = []
    for p in paths:
        p = (p or '').strip()
        if p and p not in cleaned: cleaned.append(p)
    state['servers_config'][name]['scan_paths'] = cleaned
    try:
        save_config()
        return jsonify({'success':True,'scan_paths':cleaned,'message':'已保存' if cleaned else '已恢复为扫描根目录'})
    except Exception as e:
        return jsonify({'success':False,'message':str(e)}),500

@app.route('/api/config/save', methods=['POST'])
def save_cfg():
    try: save_config(); return jsonify({'success':True,'message':'配置已保存'})
    except Exception as e: return jsonify({'success':False,'message':str(e)}),500

@app.route('/api/config/reload', methods=['POST'])
def reload_cfg():
    load_config(); load_whitelist()
    return jsonify({'success':True,'count':len(state['servers_config'])})

# ========== 连通性测试（支持选服务器） ==========
@app.route('/api/test/connectivity', methods=['POST'])
def test_conn():
    data = request.json or {}
    selected = data.get('servers', [])  # 空=全部
    servers = selected if selected else list(state['servers_config'].keys())
    tid = new_task('测试连通性')
    def run():
        update_progress(tid, total=len(servers), progress=0)
        ok, fail = 0, 0
        for i, name in enumerate(servers):
            info = state['servers_config'][name]
            add_log(tid, f"测试 {name} ({info.get('ip')}:{info.get('port',22)})...")
            ssh, err = create_ssh(name)
            if ssh:
                ssh.close()
                auth = '密钥' if info.get('key_path') else '密码'
                state['servers_config'][name]['connectivity'] = f'✅ 连通 ({auth})'
                add_log(tid, f"✅ {name} 连通成功", 'success')
                ok += 1
            else:
                state['servers_config'][name]['connectivity'] = '❌ 失败'
                add_log(tid, f"❌ {name} 失败: {err}", 'error')
                fail += 1
            update_progress(tid, progress=i+1)
        add_log(tid, f"完成: 成功 {ok}, 失败 {fail}", 'success' if fail==0 else 'error')
        finish_task(tid, {'success':ok,'fail':fail})
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'task_id':tid})

# ========== Ansible 扫描 ==========
def do_scan(selected_servers=None, from_schedule=False):
    tid = new_task('定时扫描' if from_schedule else '批量扫描')
    state['scan_reports'] = {}
    state['scan_stop'] = False
    state['current_scan_task'] = tid
    selected = selected_servers or []
    servers = selected if selected else list(state['servers_config'].keys())
    stopped = False

    def run():
        nonlocal stopped
        update_progress(tid, total=len(servers), progress=0)
        i = 0
        for i, name in enumerate(servers):
            if state['scan_stop']:
                stopped = True
                add_log(tid, f"收到停止信号，跳过剩余 {len(servers)-i} 台服务器", 'info')
                break
            info = state['servers_config'].get(name)
            if not info:
                add_log(tid, f"[{name}] 配置不存在，跳过", 'error')
                update_progress(tid, progress=i+1)
                continue
            ip = info.get('ip', '')
            paths = get_clamav_paths(name)
            rdir = paths['report_dir']
            cscan = paths['clamscan_path']
            # 扫描路径：服务器配置了 scan_paths 就用它，否则扫根目录 /
            scan_paths = [p for p in info.get('scan_paths',[]) if p.strip()] or ['/']
            scan_path_args = ' '.join(shlex.quote(p) for p in scan_paths)
            # Python端生成报告文件名，停止后也能定位到文件
            report_ts = datetime.now().strftime('%Y%m%d-%H%M')
            report_file = f'report-{report_ts}.txt'

            path_desc = '根目录 /' if scan_paths == ['/'] else f"{len(scan_paths)} 个目录: {', '.join(scan_paths)}"
            add_log(tid, f"[{name}] ({ip}) 连接并开始扫描 [{path_desc}]...")
            ssh, err = create_ssh(name)
            if not ssh:
                add_log(tid, f"[{name}] 连接失败: {err}", 'error')
                state['scan_reports'][name] = {'report_file':'', 'virus_count':0, 'full_ip':ip, 'status':'连接失败'}
                update_progress(tid, progress=i+1)
                continue
            try:
                try:
                    ssh.get_transport().set_keepalive(30)
                except Exception:
                    pass
                # tee同时输出到stdout(实时进度)和报告文件
                cmd = (
                    f"mkdir -p {rdir} && "
                    f"{cscan} -r --bell {scan_path_args} 2>&1 | tee {rdir}/{report_file}; "
                    f"echo '===REPORT_FILE:{report_file}==='; "
                    f"grep 'Infected files:' {rdir}/{report_file}"
                )
                channel = ssh.get_transport().open_session()
                channel.exec_command(cmd)

                scanned_files = 0
                last_progress_log = time.time()
                server_stopped = False

                while not channel.exit_status_ready():
                    if channel.recv_ready():
                        data = channel.recv(65536).decode(errors='replace')
                        scanned_files += data.count('\n')
                    now = time.time()
                    if now - last_progress_log > 10:
                        add_log(tid, f"[{name}] 扫描中...已扫描约{scanned_files}个文件")
                        last_progress_log = now
                    if state['scan_stop']:
                        server_stopped = True
                        stopped = True
                        add_log(tid, f"[{name}] 收到停止信号，正在终止clamscan...", 'info')
                        try:
                            ssh_kill, _ = create_ssh(name)
                            if ssh_kill:
                                ssh_kill.exec_command('pkill -9 -f clamscan')
                                ssh_kill.close()
                        except Exception:
                            pass
                        time.sleep(3)
                        break
                    time.sleep(0.5)

                # 读取剩余输出
                remaining = ''
                while channel.recv_ready():
                    remaining += channel.recv(65536).decode(errors='replace')

                virus_count = 0
                im = re.search(r'Infected files:\s*(\d+)', remaining)
                if im:
                    virus_count = int(im.group(1))
                elif server_stopped:
                    # 手动停止后报告可能没有Infected汇总行，统计FOUND行数
                    try:
                        ssh2, _ = create_ssh(name)
                        if ssh2:
                            si = ssh2.exec_command(f"grep -c ' FOUND$' {rdir}/{report_file} 2>/dev/null")
                            cnt = si[1].read().decode().strip()
                            if cnt.isdigit():
                                virus_count = int(cnt)
                            ssh2.close()
                    except Exception:
                        pass

                status = '手动停止' if server_stopped else '完成'
                state['scan_reports'][name] = {
                    'report_file': report_file,
                    'virus_count': virus_count,
                    'full_ip': ip,
                    'status': status,
                    'scanned_files': scanned_files
                }
                lv = 'error' if virus_count > 0 else 'success'
                add_log(tid, f"[{name}] {status} 报告:{report_file} 已扫描约{scanned_files}文件 感染:{virus_count}", lv)
            except Exception as e:
                add_log(tid, f"[{name}] 扫描异常: {e}", 'error')
                state['scan_reports'][name] = {'report_file':report_file, 'virus_count':0, 'full_ip':ip, 'status':'异常'}
            finally:
                ssh.close()
            update_progress(tid, progress=i+1)

        # 被停止时，剩余未扫描的服务器也记录状态
        if stopped:
            for name in servers[i+1:]:
                info = state['servers_config'].get(name, {})
                state['scan_reports'][name] = {
                    'report_file': '', 'virus_count': 0,
                    'full_ip': info.get('ip',''), 'status': '未扫描(手动停止)'
                }

        vservers = [s for s,ii in state['scan_reports'].items() if ii.get('virus_count',0)>0]
        status_text = '（手动停止）' if stopped else ''
        add_log(tid, f"扫描{status_text}完成，{len(vservers)} 台有病毒", 'error' if vservers else 'success')
        update_progress(tid, progress=100)
        history = load_history()
        record = {'time':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'servers_scanned':len(state['scan_reports']),
                  'virus_servers':vservers,'virus_total':sum(ii.get('virus_count',0) for ii in state['scan_reports'].values()),
                  'from_schedule':from_schedule,'stopped':stopped,
                  'reports':{s:{'ip':ii['full_ip'],'virus_count':ii.get('virus_count',0),'report_file':ii.get('report_file',''),'status':ii.get('status','')} for s,ii in state['scan_reports'].items()}}
        history.insert(0, record); history = history[:100]; save_history(history)
        if vservers:
            msg = f"🚨 病毒扫描告警{status_text}\n时间: {record['time']}\n扫描 {len(state['scan_reports'])} 台\n发现病毒 {len(vservers)} 台:\n"
            for s in vservers:
                msg += f"  - {s} ({state['scan_reports'][s]['full_ip']}): {state['scan_reports'][s]['virus_count']} 个\n"
            send_wechat_webhook(msg)
        elif from_schedule:
            send_wechat_webhook(f"✅ 定时扫描完成{status_text}\n时间: {record['time']}\n扫描 {len(state['scan_reports'])} 台，全部正常")
        finish_task(tid, {'virus_servers':vservers,'reports':state['scan_reports'],'stopped':stopped})
    threading.Thread(target=run, daemon=True).start()
    return tid

@app.route('/api/scan/ansible', methods=['POST'])
def run_scan():
    d = request.json or {}
    tid = do_scan(selected_servers=d.get('servers',[]))
    return jsonify({'task_id':tid})

@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    if not state.get('current_scan_task'):
        return jsonify({'success':False,'message':'当前没有正在运行的扫描任务'})
    state['scan_stop'] = True
    return jsonify({'success': True, 'message': '已发送停止信号，正在终止当前扫描...'})

@app.route('/api/scan/results', methods=['GET'])
def scan_results():
    return jsonify({'reports':[{'server':s,'ip':i['full_ip'],'report_file':i['report_file'],'virus_count':i['virus_count'],'status':i.get('status','')} for s,i in state['scan_reports'].items()]})

# ========== 病毒文件收集 ==========
@app.route('/api/virus/collect', methods=['POST'])
def collect_virus():
    tid = new_task('收集病毒文件')
    state['all_virus_files'] = []
    vservers = [s for s,i in state['scan_reports'].items() if i['virus_count']>0]
    if not vservers:
        add_log(tid, "没有发现病毒的服务器", 'error'); finish_task(tid, {'count':0}); return jsonify({'task_id':tid})
    valid = [s for s in vservers if state['servers_config'].get(s,{}).get('password') or state['servers_config'].get(s,{}).get('key_path')]
    def run():
        update_progress(tid, total=len(valid), progress=0)
        filtered = 0
        for i, server in enumerate(valid):
            info = state['servers_config'][server]
            rpt = state['scan_reports'][server]['report_file']
            add_log(tid, f"收集 {server} ({info['ip']})...")
            ssh, err = create_ssh(server)
            if not ssh:
                add_log(tid, f"{server}: 连接失败 - {err}", 'error'); update_progress(tid, progress=i+1); continue
            try:
                rdir = get_clamav_paths(server)['report_dir']
                si = ssh.exec_command(f"grep 'FOUND$' {rdir}/{rpt}")
                content = si[1].read().decode().strip()
                for line in content.split('\n'):
                    if not line or 'FOUND' not in line: continue
                    if ': ' in line:
                        pos = line.find(': '); fp = line[:pos].strip()
                        vn = line[pos+2:].strip().replace(' FOUND','').strip()
                    else:
                        parts = line.split(); fp = parts[0] if parts else line; vn = "未知"
                    if is_whitelisted(fp, vn): filtered += 1; continue
                    sz = ssh.exec_command(f"ls -lh '{fp}' 2>/dev/null | awk '{{print $5}}'")
                    fs = sz[1].read().decode().strip()
                    state['all_virus_files'].append({'server':server,'ip':info['ip'],'file_path':fp,'virus_name':vn,'file_size':fs or '未知','status':'待删除'})
                cnt = len([f for f in state['all_virus_files'] if f['server']==server])
                add_log(tid, f"{server}: {cnt} 个病毒文件", 'error' if cnt>0 else 'success')
            except Exception as e: add_log(tid, f"{server}: 失败 - {e}", 'error')
            finally: ssh.close()
            update_progress(tid, progress=i+1)
        if filtered>0: add_log(tid, f"白名单过滤掉 {filtered} 个误报")
        add_log(tid, f"共 {len(state['all_virus_files'])} 个病毒文件", 'success')
        finish_task(tid, {'count':len(state['all_virus_files'])})
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'task_id':tid})

@app.route('/api/virus/list', methods=['GET'])
def virus_list():
    return jsonify({'files':state['all_virus_files'],'count':len(state['all_virus_files'])})

@app.route('/api/virus/whitelist', methods=['POST'])
def add_whitelist():
    d = request.json or {}; indices = d.get('indices',[]); wl_type = d.get('type','path'); added = 0
    for idx in indices:
        if 0 <= idx < len(state['all_virus_files']):
            vf = state['all_virus_files'][idx]
            pattern = vf['file_path'] if wl_type=='path' else vf['virus_name']
            if not any(i.get('pattern')==pattern for i in state['whitelist']):
                state['whitelist'].append({'type':wl_type,'pattern':pattern,'add_time':datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
                added += 1
    save_whitelist()
    return jsonify({'success':True,'added':added,'total':len(state['whitelist'])})

@app.route('/api/virus/whitelist', methods=['GET'])
def get_whitelist(): return jsonify({'whitelist':state['whitelist']})

@app.route('/api/virus/whitelist/<int:idx>', methods=['DELETE'])
def del_whitelist(idx):
    if 0 <= idx < len(state['whitelist']):
        del state['whitelist'][idx]; save_whitelist(); return jsonify({'success':True})
    return jsonify({'success':False}),404

@app.route('/api/virus/delete', methods=['POST'])
def delete_virus():
    tid = new_task('删除病毒文件')
    d = request.json or {}; indices = d.get('indices',[])
    targets = [state['all_virus_files'][i] for i in indices if 0<=i<len(state['all_virus_files'])]
    if not targets: add_log(tid, "未选择文件", 'error'); finish_task(tid, {'success':0,'fail':0}); return jsonify({'task_id':tid})
    def run():
        total = len(targets); update_progress(tid, total=total, progress=0); ok, fail = 0, 0
        for i, vf in enumerate(targets):
            add_log(tid, f"删除: {vf['server']} - {vf['file_path']} ({vf['virus_name']})")
            ssh, err = create_ssh(vf['server'])
            if not ssh: add_log(tid, f"失败: {err}", 'error'); fail += 1
            else:
                try:
                    ssh.exec_command(f"rm -f '{vf['file_path']}'"); vf['status']='已删除'; ok += 1
                    add_log(tid, f"✅ 已删除: {vf['file_path']}", 'success')
                except Exception as e: add_log(tid, f"失败: {e}", 'error'); fail += 1
                finally: ssh.close()
            update_progress(tid, progress=i+1)
        state['all_virus_files'] = [f for f in state['all_virus_files'] if f['status']!='已删除']
        add_log(tid, f"删除完成: 成功 {ok}, 失败 {fail}", 'success' if fail==0 else 'error')
        finish_task(tid, {'success':ok,'fail':fail})
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'task_id':tid})

# ========== ClamAV（支持选目标服务器） ==========
@app.route('/api/clamav/status', methods=['POST'])
def clamav_status():
    tid = new_task('检查ClamAV状态')
    d = request.json or {}
    target = d.get('server', '')
    def run():
        if not target:
            add_log(tid, "请先在下拉框选择一台目标服务器", 'error'); finish_task(tid, {'error':'未选择目标服务器'}); return
        ssh, err = create_ssh(target)
        label = f"服务器 {target}"
        if not ssh:
            add_log(tid, f"连接 {label} 失败: {err}", 'error'); finish_task(tid, {'error':err}); return
        try:
            paths = get_clamav_paths(target)
            cscan = paths['clamscan_path']
            fclam = paths['freshclam_path']
            dbdir = paths['db_dir']
            add_log(tid, f"检查 {label} ClamAV版本 (clamscan={cscan})...")
            si = ssh.exec_command(f'{cscan} --version 2>/dev/null || clamd --version 2>/dev/null')
            ver = si[1].read().decode().strip()
            add_log(tid, f"版本: {ver}")
            si = ssh.exec_command(f'ls -lh {dbdir}/*.cvd {dbdir}/*.cld 2>/dev/null')
            dbf = si[1].read().decode().strip()
            add_log(tid, f"病毒库文件 ({dbdir}):\n{dbf}")
            si = ssh.exec_command(f'stat -c "%y" {dbdir}/main.cvd 2>/dev/null || stat -c "%y" {dbdir}/main.cld 2>/dev/null')
            dbd = si[1].read().decode().strip()
            add_log(tid, f"病毒库日期: {dbd}")
            si = ssh.exec_command(f'which {fclam} 2>/dev/null && echo "freshclam: {fclam}"')
            add_log(tid, si[1].read().decode().strip())
            finish_task(tid, {'version':ver,'db_files':dbf,'db_date':dbd,'target':label,'clamscan_path':cscan,'freshclam_path':fclam,'db_dir':dbdir})
        except Exception as e:
            add_log(tid, f"失败: {e}", 'error'); finish_task(tid, {'error':str(e)})
        finally: ssh.close()
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'task_id':tid})

@app.route('/api/clamav/update', methods=['POST'])
def clamav_update():
    tid = new_task('更新病毒库')
    d = request.json or {}
    target = d.get('server', '')
    def run():
        if not target:
            add_log(tid, "请先在下拉框选择一台目标服务器", 'error'); finish_task(tid, {'error':'未选择目标服务器'}); return
        ssh, err = create_ssh(target)
        label = f"服务器 {target}"
        if not ssh:
            add_log(tid, f"连接 {label} 失败: {err}", 'error'); finish_task(tid, {'error':err}); return
        try:
            paths = get_clamav_paths(target)
            fclam = paths['freshclam_path']
            dbdir = paths['db_dir']
            add_log(tid, f"在 {label} 执行 {fclam} 更新病毒库 (库目录:{dbdir})...")
            si = ssh.exec_command(f'{fclam} 2>&1', timeout=300)
            while True:
                line = si[1].readline()
                if not line: break
                line = line.rstrip()
                if line: add_log(tid, line)
            add_log(tid, f"{label} 病毒库更新完成", 'success')
            si = ssh.exec_command(f'stat -c "%y" {dbdir}/main.cvd 2>/dev/null || stat -c "%y" {dbdir}/main.cld 2>/dev/null')
            dbd = si[1].read().decode().strip()
            si = ssh.exec_command(f'ls -lh {dbdir}/*.cvd {dbdir}/*.cld 2>/dev/null')
            dbf = si[1].read().decode().strip()
            finish_task(tid, {'db_date':dbd,'db_files':dbf,'target':label,'freshclam_path':fclam,'db_dir':dbdir})
        except Exception as e:
            add_log(tid, f"失败: {e}", 'error'); finish_task(tid, {'error':str(e)})
        finally: ssh.close()
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'task_id':tid})

# ========== 历史记录 ==========
@app.route('/api/history', methods=['GET'])
def get_history():
    return jsonify({'history':load_history()})

# ========== 定时任务 ==========
@app.route('/api/schedule', methods=['GET'])
def get_schedule(): return jsonify({'schedule':state['schedule']})

@app.route('/api/schedule', methods=['POST'])
def update_schedule():
    d = request.json or {}
    state['schedule'].update({
        'enabled': d.get('enabled', False),
        'cron': d.get('cron', state['schedule']['cron']),
        'schedule_servers': d.get('schedule_servers', state['schedule'].get('schedule_servers', [])),
        'webhook': d.get('webhook', state['schedule']['webhook'])
    })
    save_config()
    return jsonify({'success':True})

@app.route('/api/schedule/run-now', methods=['POST'])
def schedule_run_now():
    """立即执行一次定时扫描（用定时任务配置的服务器列表），方便测试"""
    srv = state['schedule'].get('schedule_servers', [])
    tid = do_scan(selected_servers=srv, from_schedule=True)
    return jsonify({'task_id': tid, 'message': f'已触发，目标: {"全部服务器" if not srv else str(len(srv))+"台"}'})

@app.route('/api/schedule/test-push', methods=['POST'])
def test_push():
    d = request.json or {}
    send_wechat_webhook("✅ 病毒扫描系统测试推送", url=d.get('webhook'))
    return jsonify({'success':True,'message':'已发送测试消息（请看企业微信群，失败请看后端控制台 [webhook] 日志）'})

@app.route('/api/task/<tid>', methods=['GET'])
def get_task(tid):
    t = state['tasks'].get(tid)
    if not t: return jsonify({'error':'不存在'}),404
    return jsonify(t)

# 定时扫描线程
def cron_hit(expr, now):
    """简单5段cron匹配: 分 时 日 月 周。支持 * 与具体数字；不支持列表/步进/范围。
    星期采用标准 cron 约定: 0=周日, 1=周一, ..., 6=周六, 7=周日。
    返回 (是否命中, 错误信息)。"""
    parts = (expr or '').split()
    if len(parts) != 5:
        return False, f"cron 需 5 段(分 时 日 月 周)，当前 '{expr}' 只有 {len(parts)} 段"
    def match(field, cur):
        if field == '*': return True
        try: return int(field) == cur
        except ValueError: return False
    try:
        if not match(parts[0], now.minute): return False, None
        if not match(parts[1], now.hour):   return False, None
        if not match(parts[2], now.day):    return False, None
        if not match(parts[3], now.month):  return False, None
        # 星期: 标准 cron 0=周日..6=周六, 7=周日; python isoweekday() 1=周一..7=周日, %7 后 0=周日
        dow_field = parts[4]
        if dow_field != '*':
            try:
                v = int(dow_field)
                if v == 7: v = 0
                if v != (now.isoweekday() % 7): return False, None
            except ValueError:
                return False, f"cron 星期字段无法解析: {dow_field}"
    except Exception as e:
        return False, f"cron 解析异常: {e}"
    return True, None

def schedule_loop():
    last_fire = None
    last_warn = None
    while True:
        try:
            if state['schedule'].get('enabled'):
                now = datetime.now()
                hit, err = cron_hit(state['schedule'].get('cron','0 9 * * 1'), now)
                if err:
                    # 同一分钟只警告一次，避免每30秒刷屏
                    key = now.strftime('%Y-%m-%d %H:%M')
                    if last_warn != key:
                        last_warn = key
                        print(f"[定时] {err}")
                elif hit:
                    mark = now.strftime('%Y-%m-%d %H:%M')
                    if last_fire != mark:
                        last_fire = mark
                        srv = state['schedule'].get('schedule_servers', [])
                        print(f"[定时] 触发扫描 {now}，目标: {'全部' if not srv else str(len(srv))+'台'}")
                        do_scan(selected_servers=srv, from_schedule=True)
        except Exception as e:
            print(f"[定时] {e}")
        time.sleep(30)

load_config(); load_whitelist()
_sched = state['schedule']
print(f"[定时] 调度线程已启动 | 启用: {_sched.get('enabled')} | cron: {_sched.get('cron')} | 目标: {'全部' if not _sched.get('schedule_servers') else str(len(_sched['schedule_servers']))+'台'}")
threading.Thread(target=schedule_loop, daemon=True).start()

if __name__ == '__main__':
    print("="*50)
    print("服务器病毒扫描管理系统 B/S版")
    print(f"已加载 {len(state['servers_config'])} 台服务器")
    print("访问: http://127.0.0.1:5004")
    print("="*50)
    app.run(host='0.0.0.0', port=5004, debug=False, threaded=True)


