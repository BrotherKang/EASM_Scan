#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EASM (External Attack Surface Management) 掃描工具
使用 python-nmap、openpyxl 和 requests 進行掃描並產出多工作表 Excel 報告
支援兩階段掃描模式與多執行緒並行處理
"""

import nmap
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
import requests
import json
import sys
import os
from datetime import datetime
from collections import defaultdict
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import re

# 常數定義
HISTORY_FILE = 'scan_history.json'
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888]
IP_API_URL = 'http://ip-api.com/json/{}'
REPORT_DIR_DEFAULT = 'Report'  # 新增：預設報告資料夾名稱

# 多執行緒設定（可在程式開頭調整）
MAX_WORKERS = 1  # 預設 1 個執行緒，可根據需求調整（建議 5-10）


class EASMScanner:

    def __init__(self, target_file, report_dir):
        """初始化掃描器"""
        self.target_file = target_file
        self.report_dir = report_dir
        # 確保報告資料夾存在
        os.makedirs(self.report_dir, exist_ok=True)
        self.scan_results = []
        # 載入歷史掃描記錄
        self.history = self.load_history()
        # 漏洞清單
        self.vulnerabilities = []
        # 變動項目
        self.changes = []
        # Port 開啟統計
        self.port_stats = defaultdict(lambda: {'count': 0, 'service': ''})
        # 用於執行緒安全的資料寫入
        self.lock = threading.Lock()  
        
    def load_history(self):
        """載入歷史掃描記錄"""
        history_path = os.path.join(self.report_dir, HISTORY_FILE)
        if os.path.exists(history_path):
            try:
                with open(history_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"警告：無法讀取歷史記錄：{e}")
                return {}
        return {}
    
    def save_history(self):
        """儲存歷史掃描記錄"""
        history_data = {}
        for result in self.scan_results:
            ip = result['ip']
            history_data[ip] = {
                'ports': result['ports'],
                'services': result['services'],
                'scan_time': result['scan_time']
            }
        
        history_path = os.path.join(self.report_dir, HISTORY_FILE)
        with open(history_path, 'w', encoding='utf-8') as f:
            json.dump(history_data, f, ensure_ascii=False, indent=2)

    def get_geo_info(self, ip):
        """查詢 IP 地理位置與 ISP"""
        try:
            response = requests.get(IP_API_URL.format(ip), timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'N/A'),
                    'region': data.get('regionName', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'isp': data.get('isp', 'N/A'),
                    'org': data.get('org', 'N/A')
                }
        except Exception as e:
            print(f"警告：無法查詢 {ip} 的地理位置：{e}")
        return {
            'country': 'N/A',
            'region': 'N/A',
            'city': 'N/A',
            'isp': 'N/A',
            'org': 'N/A'
        }
    
    def fast_scan(self, ip):
        """第一階段：快速全 Port 掃描（1-65535）"""
        nm = nmap.PortScanner()
        open_ports = []
        
        try:
            print(f"  [+] [{ip}] 第一階段：快速全 Port 掃描中...")
            # 使用 -p 1-65535 --open -T4 進行快速掃描
            nm.scan(ip, arguments='-p 1-65535 --open -T4')
            
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    ports = nm[ip][proto].keys()
                    for port in ports:
                        port_info = nm[ip][proto][port]
                        if port_info.get('state') == 'open':
                            open_ports.append(port)
            
            print(f"  [+] [{ip}] 發現 {len(open_ports)} 個開啟的 Port")
            return sorted(open_ports)
            
        except Exception as e:
            print(f"  [!] [{ip}] 第一階段掃描錯誤：{e}")
            return []
    
    def deep_scan(self, ip, open_ports):
        """第二階段：針對性深度掃描（修正：加入 -Pn 跳過主機發現）"""
        if not open_ports:
            return None
        
        nm = nmap.PortScanner()
        
        # 如果 Port 數量過多，分批掃描（每批最多 100 個 Port）
        MAX_PORTS_PER_SCAN = 100
        
        try:
            if len(open_ports) > MAX_PORTS_PER_SCAN:
                print(f"  [+] [{ip}] Port 數量較多 ({len(open_ports)} 個)，將分批掃描...")
                # 分批處理
                all_results_nm = None
                for i in range(0, len(open_ports), MAX_PORTS_PER_SCAN):
                    batch = open_ports[i:i+MAX_PORTS_PER_SCAN]
                    print(f"  [+] [{ip}] 批次 {i//MAX_PORTS_PER_SCAN + 1}：掃描 {len(batch)} 個 Port...")
                    
                    ports_str = ','.join(map(str, batch))
                    # 關鍵：加入 -Pn 跳過主機發現（因為第一階段已確認主機在線）
                    # 不需要 --open，因為這些 Port 已經在第一階段確認是開啟的
                    scan_args = f'-Pn -p {ports_str} -sV -sC --script=ssl-enum-ciphers,ssl-cert,http-security-headers,vuln --host-timeout 300s'
                    
                    try:
                        batch_nm = nmap.PortScanner()
                        batch_nm.scan(ip, arguments=scan_args)
                        
                        # 檢查掃描狀態
                        if ip in batch_nm.all_hosts():
                            all_results_nm = batch_nm  # 保存最後一次成功的掃描結果
                            print(f"  [+] [{ip}] 批次 {i//MAX_PORTS_PER_SCAN + 1} 掃描成功")
                        else:
                            print(f"  [!] [{ip}] 批次 {i//MAX_PORTS_PER_SCAN + 1} 主機不在結果中")
                    except Exception as e:
                        print(f"  [!] [{ip}] 批次 {i//MAX_PORTS_PER_SCAN + 1} 掃描失敗：{e}")
                        continue
                
                # 返回最後一次成功的掃描結果
                if all_results_nm and ip in all_results_nm.all_hosts():
                    return all_results_nm
                else:
                    print(f"  [!] [{ip}] 所有批次掃描均失敗或主機不在結果中")
                    return None
            else:
                # Port 數量不多，直接掃描
                print(f"  [+] [{ip}] 第二階段：深度掃描 {len(open_ports)} 個 Port...")
                ports_str = ','.join(map(str, open_ports))
                # 關鍵修正：加入 -Pn 參數跳過主機發現
                # 不需要 --open，因為這些 Port 已經在第一階段確認是開啟的
                scan_args = f'-Pn -p {ports_str} -sV -sC --script=ssl-enum-ciphers,ssl-cert,http-security-headers,vuln --host-timeout 300s'
                
                print(f"  [*] [{ip}] 執行 Nmap 掃描，參數：{scan_args}")
                
                try:
                    nm.scan(ip, arguments=scan_args)
                except nmap.PortScannerError as e:
                    print(f"  [!] [{ip}] Nmap 掃描錯誤：{e}")
                    return None
                
                # 檢查掃描狀態
                if ip not in nm.all_hosts():
                    print(f"  [!] [{ip}] 深度掃描後主機不在結果中")
                    # 詳細診斷
                    try:
                        scan_info = nm.scaninfo()
                        print(f"  [*] [{ip}] 掃描資訊：{scan_info}")
                    except Exception as e:
                        print(f"  [*] [{ip}] 無法獲取掃描資訊：{e}")
                    
                    # 可能的原因分析
                    print(f"  [*] [{ip}] 可能原因：")
                    print(f"      - 主機在兩次掃描之間離線")
                    print(f"      - Port 狀態在掃描期間改變")
                    print(f"      - Nmap 主機發現階段失敗（應已使用 -Pn 避免）")
                    
                    return None
                
                # 檢查是否有任何 Port 被掃描到
                has_ports = False
                port_count = 0
                for proto in nm[ip].all_protocols():
                    ports = list(nm[ip][proto].keys())
                    port_count += len(ports)
                    if ports:
                        has_ports = True
                
                if not has_ports:
                    print(f"  [!] [{ip}] 深度掃描未發現任何 Port 資料")
                    print(f"  [*] [{ip}] 可能原因：所有 Port 在深度掃描時狀態已改變")
                    return None
                
                print(f"  [+] [{ip}] 深度掃描完成，發現 {port_count} 個 Port")
                return nm
            
        except nmap.PortScannerError as e:
            print(f"  [!] [{ip}] Nmap PortScanner 錯誤：{e}")
            return None
        except Exception as e:
            print(f"  [!] [{ip}] 第二階段掃描發生異常：{type(e).__name__}: {e}")
            import traceback
            print(f"  [*] 詳細錯誤：\n{traceback.format_exc()}")
            return None
    
    def scan_target(self, ip, index, total):
        """掃描單一目標（兩階段掃描）"""
        print(f"\n[+] Scanning {ip} ({index}/{total})...")
        
        result = {
            'ip': ip,
            'scan_time': datetime.now().isoformat(),
            'ports': [],
            'services': {},
            'vulnerabilities': [],
            'ssl_info': {},
            'status': '第一次掃測',
            'location': {},
            'raw_output': ''
        }
        
        # 查詢地理位置
        result['location'] = self.get_geo_info(ip)
        time.sleep(0.5)  # 避免 API 請求過於頻繁
        
        try:
            # 第一階段：快速全 Port 掃描
            open_ports = self.fast_scan(ip)
            
            if not open_ports:
                result['status'] = '主機無回應或無開啟 Port'
                result['raw_output'] = '未發現任何開啟的 Port'
                with self.lock:
                    self.scan_results.append(result)
                return result
            
            # 第二階段：針對開啟的 Port 進行深度掃描
            nm = self.deep_scan(ip, open_ports)
            
            if nm is None:
                # 嘗試獲取更多錯誤資訊
                error_msg = '深度掃描執行失敗'
                try:
                    # 檢查是否是 Port 數量過多導致的問題
                    if len(open_ports) > 1000:
                        error_msg = f'深度掃描失敗：開啟的 Port 數量過多 ({len(open_ports)} 個)，建議分批掃描'
                    else:
                        error_msg = f'深度掃描失敗：可能原因包括 Nmap 參數錯誤、掃描超時或主機無回應'
                except:
                    pass
                
                result['status'] = '深度掃描失敗'
                result['raw_output'] = error_msg
                # 即使深度掃描失敗，也記錄第一階段發現的 Port
                result['ports'] = open_ports
                with self.lock:
                    self.scan_results.append(result)
                return result
            
            # 解析掃描結果
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                for port in ports:
                    port_info = nm[ip][proto][port]
                    service_name = port_info.get('name', 'unknown')
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')
                    
                    result['ports'].append(port)
                    result['services'][str(port)] = {
                        'name': service_name,
                        'product': product,
                        'version': version,
                        'state': port_info.get('state', 'unknown'),
                        'script_output': port_info.get('script', {})
                    }
                    
                    # 統計 Port 開啟數量（執行緒安全）
                    with self.lock:
                        self.port_stats[port]['count'] += 1
                        if not self.port_stats[port]['service']:
                            self.port_stats[port]['service'] = service_name
                    
                    # 檢查漏洞
                    self.check_vulnerabilities(ip, port, port_info, result)
            
            # 比對歷史記錄
            self.compare_with_history(ip, result)
            
            # 儲存原始輸出
            result['raw_output'] = str(nm[ip])
            
        except Exception as e:
            print(f"  [!] [{ip}] 掃描時發生問題：{e}")
            result['status'] = f'掃描錯誤：{str(e)}'
            result['raw_output'] = str(e)
        
        # 執行緒安全地加入結果
        with self.lock:
            self.scan_results.append(result)
        
        return result
    
    def check_vulnerabilities(self, ip, port, port_info, result):
        """檢查漏洞與安全問題"""
        port_num = port
        service_name = port_info.get('name', 'unknown')
        product = port_info.get('product', '')
        version = port_info.get('version', '')
        script_output = port_info.get('script', {})
        
        # 檢查 SSL/TLS 問題
        if port_num in [443, 8443] or 'ssl' in service_name.lower() or 'https' in service_name.lower():
            ssl_info = script_output.get('ssl-enum-ciphers', '')
            ssl_cert = script_output.get('ssl-cert', '')
            
            if ssl_info or ssl_cert:
                result['ssl_info'][str(port_num)] = ssl_info or ssl_cert
                # 檢查是否使用舊版 TLS
                ssl_text = str(ssl_info) + str(ssl_cert)
                if 'TLSv1.0' in ssl_text or 'TLSv1.1' in ssl_text:
                    vuln = {
                        'ip': ip,
                        'port': port_num,
                        'protocol': 'tcp',
                        'service': service_name,
                        'type': 'SSL/TLS 過時',
                        'port_info': f'Port {port_num}',
                        'description': '使用過時的 TLS 版本 (TLSv1.0/1.1)',
                        'recommendation': '升級至 TLSv1.2 或更高版本'
                    }
                    with self.lock:
                        self.vulnerabilities.append(vuln)
                    result['vulnerabilities'].append(vuln)
        
        # 檢查 HTTP 安全標頭
        if port_num in [80, 443, 8080, 8443, 8000, 8888]:
            headers_info = script_output.get('http-security-headers', '')
            hsts_info = script_output.get('http-hsts', '')
            
            if headers_info or hsts_info:
                headers_text = str(headers_info) + str(hsts_info)
                if 'Strict-Transport-Security' not in headers_text and 'HSTS' not in headers_text:
                    vuln = {
                        'ip': ip,
                        'port': port_num,
                        'protocol': 'tcp',
                        'service': service_name,
                        'type': 'HSTS 缺失',
                        'port_info': f'Port {port_num}',
                        'description': '缺少 HSTS (HTTP Strict Transport Security) 標頭',
                        'recommendation': '在 Web 伺服器設定中加入 Strict-Transport-Security 標頭'
                    }
                    with self.lock:
                        self.vulnerabilities.append(vuln)
                    result['vulnerabilities'].append(vuln)
        
        # 檢查 Nmap 漏洞腳本結果
        vuln_scripts = ['vuln', 'vulners', 'exploit']
        for vuln_script in vuln_scripts:
            if vuln_script in script_output:
                vuln_data = script_output[vuln_script]
                if isinstance(vuln_data, str) and ('CVE' in vuln_data or 'VULNERABLE' in vuln_data.upper()):
                    # 提取 CVE 編號（如果有的話）
                    cve_match = None
                    if 'CVE-' in vuln_data:
                        cve_pattern = r'CVE-\d{4}-\d{4,7}'
                        matches = re.findall(cve_pattern, vuln_data)
                        if matches:
                            cve_match = ', '.join(matches[:3])  # 最多顯示 3 個 CVE
                    
                    description = vuln_data[:300] if len(vuln_data) > 300 else vuln_data
                    if cve_match:
                        description = f"CVE: {cve_match}\n{description}"
                    
                    vuln = {
                        'ip': ip,
                        'port': port_num,
                        'protocol': 'tcp',
                        'service': service_name,
                        'type': 'CVE 漏洞',
                        'port_info': f'Port {port_num}',
                        'description': description,
                        'recommendation': f'檢查並修補 {product} {version} 的已知漏洞'
                    }
                    with self.lock:
                        self.vulnerabilities.append(vuln)
                    result['vulnerabilities'].append(vuln)
                    break  # 每個 Port 只記錄一次 CVE 漏洞
        
        # 檢查過時的服務版本
        if product and version:
            old_versions = ['1.0', '2.0', '3.0']
            for old_ver in old_versions:
                if old_ver in version and len(version) < 10:  # 避免誤判
                    vuln = {
                        'ip': ip,
                        'port': port_num,
                        'protocol': 'tcp',
                        'service': service_name,
                        'type': '過時版本',
                        'port_info': f'Port {port_num}',
                        'description': f'使用過時版本：{product} {version}',
                        'recommendation': f'升級 {product} 至最新版本'
                    }
                    with self.lock:
                        self.vulnerabilities.append(vuln)
                    result['vulnerabilities'].append(vuln)
                    break
    
    def compare_with_history(self, ip, current_result):
        """與歷史記錄比對，找出變動"""
        with self.lock:
            if ip not in self.history:
                current_result['status'] = '第一次掃測'
                self.changes.append({
                    'ip': ip,
                    'type': '新增 IP',
                    'details': '首次發現此 IP'
                })
                return
            
            old_data = self.history[ip]
            old_ports = set(old_data.get('ports', []))
            current_ports = set(current_result['ports'])
            
            # 檢查新增的 Port
            new_ports = current_ports - old_ports
            for port in new_ports:
                self.changes.append({
                    'ip': ip,
                    'type': 'Port 開啟',
                    'details': f'Port {port} 從關閉變為開啟'
                })
            
            # 檢查關閉的 Port
            closed_ports = old_ports - current_ports
            for port in closed_ports:
                self.changes.append({
                    'ip': ip,
                    'type': 'Port 關閉',
                    'details': f'Port {port} 從開啟變為關閉'
                })
            
            # 檢查服務版本變更
            old_services = old_data.get('services', {})
            current_services = current_result['services']
            
            for port in current_ports & old_ports:
                port_str = str(port)
                if port_str in old_services and port_str in current_services:
                    old_service = old_services[port_str]
                    current_service = current_services[port_str]
                    
                    old_version = f"{old_service.get('product', '')} {old_service.get('version', '')}".strip()
                    current_version = f"{current_service.get('product', '')} {current_service.get('version', '')}".strip()
                    
                    if old_version != current_version:
                        self.changes.append({
                            'ip': ip,
                            'type': '服務版本變更',
                            'details': f'Port {port}: {old_version} -> {current_version}'
                        })
            
            if not new_ports and not closed_ports:
                current_result['status'] = '無變動'
            else:
                current_result['status'] = '有變動'
    
    def generate_excel_report(self):
        """生成 Excel 報告"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f'EASM_Report_{timestamp}.xlsx'
        report_path = os.path.join(self.report_dir, filename)
        wb = openpyxl.Workbook()
        
        # 移除預設工作表
        if 'Sheet' in wb.sheetnames:
            wb.remove(wb['Sheet'])
        
        # 定義標題樣式
        header_fill = PatternFill(start_color='CCCCCC', end_color='CCCCCC', fill_type='solid')
        header_font = Font(bold=True, size=11)
        
        # 工作表 1: 掃描摘要
        self.create_summary_sheet(wb, header_fill, header_font)
        
        # 工作表 2: 漏洞清單
        self.create_vulnerability_sheet(wb, header_fill, header_font)
        
        # 工作表 3: 變動比對
        self.create_change_log_sheet(wb, header_fill, header_font)
        
        # 工作表 4: Port 開啟統計
        self.create_port_stats_sheet(wb, header_fill, header_font)
        
        # 工作表 5: 詳細資料
        self.create_raw_data_sheet(wb, header_fill, header_font)
        
        # 儲存檔案
        wb.save(report_path)
        print(f"\n報告已生成：{report_path}")
        return report_path
    
    def create_summary_sheet(self, wb, header_fill, header_font):
        """建立掃描摘要工作表"""
        ws = wb.create_sheet('掃描摘要', 0)
        
        headers = ['掃描日期', '掃描 IP 總數', '發現風險 IP 數', '異動 IP 數', 
                   '高風險漏洞總數', 'SSL/TLS 不合規數量']
        
        # 寫入標題
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # 計算統計數據
        scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total_ips = len(self.scan_results)
        risk_ips = len(set(v['ip'] for v in self.vulnerabilities))
        changed_ips = len(set(c['ip'] for c in self.changes))
        total_vulns = len(self.vulnerabilities)
        ssl_non_compliant = len([v for v in self.vulnerabilities if 'SSL/TLS' in v['type']])
        
        # 寫入數據
        data = [scan_date, total_ips, risk_ips, changed_ips, total_vulns, ssl_non_compliant]
        for col, value in enumerate(data, 1):
            cell = ws.cell(row=2, column=col, value=value)
            cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # 調整欄寬
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 20
    
    def create_vulnerability_sheet(self, wb, header_fill, header_font):
        """建立漏洞清單工作表（Port 與描述分離）"""
        ws = wb.create_sheet('漏洞清單', 1)
        
        # 修改欄位：將 Port 資訊從描述中分離出來
        headers = ['IP Address', 'Port/Protocol', 'Service Name', '漏洞類型', 
                   'Port', '詳細描述', '修補建議']
        
        # 寫入標題
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # 寫入漏洞數據
        for row, vuln in enumerate(self.vulnerabilities, 2):
            ws.cell(row=row, column=1, value=vuln['ip'])
            ws.cell(row=row, column=2, value=f"{vuln['port']}/{vuln['protocol']}")
            ws.cell(row=row, column=3, value=vuln['service'])
            ws.cell(row=row, column=4, value=vuln['type'])
            # Port 資訊（從 port_info 欄位取得，如果沒有則使用 port 欄位）
            port_info = vuln.get('port_info', f"Port {vuln['port']}")
            ws.cell(row=row, column=5, value=port_info)
            # 詳細描述（已移除 Port 資訊）
            ws.cell(row=row, column=6, value=vuln['description'])
            ws.cell(row=row, column=7, value=vuln['recommendation'])
        
        # 調整欄寬
        column_widths = [15, 15, 20, 20, 15, 50, 40]
        for col, width in enumerate(column_widths, 1):
            ws.column_dimensions[get_column_letter(col)].width = width
        
        # 設定文字自動換行
        for row in range(2, len(self.vulnerabilities) + 2):
            for col in range(1, 8):
                ws.cell(row=row, column=col).alignment = Alignment(wrap_text=True, vertical='top')
    
    def create_change_log_sheet(self, wb, header_fill, header_font):
        """建立變動比對工作表"""
        ws = wb.create_sheet('變動比對', 2)
        
        headers = ['IP Address', '變動類型', '變更詳情']
        
        # 寫入標題
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # 寫入變動數據
        for row, change in enumerate(self.changes, 2):
            ws.cell(row=row, column=1, value=change['ip'])
            ws.cell(row=row, column=2, value=change['type'])
            ws.cell(row=row, column=3, value=change['details'])
        
        # 調整欄寬
        column_widths = [15, 20, 50]
        for col, width in enumerate(column_widths, 1):
            ws.column_dimensions[get_column_letter(col)].width = width
        
        # 設定文字自動換行
        for row in range(2, len(self.changes) + 2):
            for col in range(1, 4):
                ws.cell(row=row, column=col).alignment = Alignment(wrap_text=True, vertical='top')
    
    def create_port_stats_sheet(self, wb, header_fill, header_font):
        """建立 Port 開啟統計工作表"""
        ws = wb.create_sheet('Port 開啟統計', 3)
        
        headers = ['Port 號碼', '服務名稱', '開啟數量', '佔比 (%)']
        
        # 寫入標題
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # 計算總數
        total_ips = len(self.scan_results)
        if total_ips == 0:
            total_ips = 1  # 避免除零
        
        # 排序 Port 統計（按開啟數量降序）
        sorted_ports = sorted(self.port_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        
        # 寫入數據
        for row, (port, stats) in enumerate(sorted_ports, 2):
            count = stats['count']
            percentage = (count / total_ips) * 100
            
            ws.cell(row=row, column=1, value=port)
            ws.cell(row=row, column=2, value=stats['service'])
            ws.cell(row=row, column=3, value=count)
            ws.cell(row=row, column=4, value=f"{percentage:.2f}%")
        
        # 調整欄寬
        column_widths = [15, 25, 15, 15]
        for col, width in enumerate(column_widths, 1):
            ws.column_dimensions[get_column_letter(col)].width = width
        
        # 設定對齊
        for row in range(2, len(sorted_ports) + 2):
            ws.cell(row=row, column=1).alignment = Alignment(horizontal='center')
            ws.cell(row=row, column=3).alignment = Alignment(horizontal='center')
            ws.cell(row=row, column=4).alignment = Alignment(horizontal='center')
    
    def create_raw_data_sheet(self, wb, header_fill, header_font):
        """建立詳細資料工作表"""
        ws = wb.create_sheet('詳細資料', 4)
        
        headers = ['IP', '地理位置', 'ISP', 'Port 清單', 'SSL/TLS 狀態', 
                   '完整 Nmap 輸出', '掃測狀態標記']
        
        # 寫入標題
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # 寫入詳細數據
        for row, result in enumerate(self.scan_results, 2):
            location = result.get('location', {})
            location_str = f"{location.get('country', 'N/A')}, {location.get('city', 'N/A')}"
            isp = location.get('isp', 'N/A')
            ports_str = ', '.join(map(str, result.get('ports', [])))
            
            ssl_status = 'N/A'
            if result.get('ssl_info'):
                ssl_status = '已檢查'
                # 檢查是否有 SSL 問題
                for port, ssl_data in result['ssl_info'].items():
                    if isinstance(ssl_data, str) and ('TLSv1.0' in ssl_data or 'TLSv1.1' in ssl_data):
                        ssl_status = '不合規'
                        break
            
            ws.cell(row=row, column=1, value=result['ip'])
            ws.cell(row=row, column=2, value=location_str)
            ws.cell(row=row, column=3, value=isp)
            ws.cell(row=row, column=4, value=ports_str)
            ws.cell(row=row, column=5, value=ssl_status)
            ws.cell(row=row, column=6, value=result.get('raw_output', '')[:5000])  # 限制長度
            ws.cell(row=row, column=7, value=result.get('status', '正常'))
        
        # 調整欄寬
        column_widths = [15, 25, 30, 30, 15, 60, 20]
        for col, width in enumerate(column_widths, 1):
            ws.column_dimensions[get_column_letter(col)].width = width
        
        # 設定文字自動換行
        for row in range(2, len(self.scan_results) + 2):
            for col in range(1, 8):
                ws.cell(row=row, column=col).alignment = Alignment(wrap_text=True, vertical='top')
    
    def run(self):
        """執行完整掃描流程（多執行緒版本）"""
        # 讀取目標清單
        try:
            with open(self.target_file, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"錯誤：找不到目標檔案 {self.target_file}")
            return
        except Exception as e:
            print(f"錯誤：讀取目標檔案時發生問題：{e}")
            return
        
        if not targets:
            print("錯誤：目標清單為空")
            return
        
        print("=" * 70)
        print(f"EASM 掃描工具 - 兩階段掃描模式 + 多執行緒並行處理")
        print(f"目標數量：{len(targets)}")
        print(f"執行緒數：{MAX_WORKERS}")
        print(f"掃描範圍：Port 1-65535")
        print(f"報告資料夾：{self.report_dir}")
        print("=" * 70)
        
        # 使用 ThreadPoolExecutor 進行多執行緒掃描
        completed = 0
        failed = 0
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # 提交所有掃描任務
            future_to_target = {
                executor.submit(self.scan_target, target, i+1, len(targets)): target 
                for i, target in enumerate(targets)
            }
            
            # 處理完成的任務
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    completed += 1
                    print(f"  [✓] [{target}] 掃描完成 ({completed}/{len(targets)})")
                except KeyboardInterrupt:
                    print("\n\n掃描已中斷")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                except Exception as e:
                    failed += 1
                    print(f"  [✗] [{target}] 掃描失敗：{e} ({completed + failed}/{len(targets)})")
                    continue
        
        print("\n" + "=" * 70)
        print("掃描完成，正在生成報告...")
        print(f"  成功：{completed} 個")
        print(f"  失敗：{failed} 個")
        print("=" * 70)
        
        # 儲存歷史記錄
        self.save_history()
        
        # 生成 Excel 報告
        report_file = self.generate_excel_report()
        
        print(f"\n掃描摘要：")
        print(f"  - 掃描 IP 數：{len(self.scan_results)}")
        print(f"  - 發現漏洞數：{len(self.vulnerabilities)}")
        print(f"  - 變動項目數：{len(self.changes)}")
        print(f"  - 報告檔案：{report_file}")


def main():
    """主程式入口"""
    if len(sys.argv) < 2:
        print("使用方法：python scan.py <目標清單檔案>")
        print("範例：python scan.py targets.txt")
        print("範例：python scan.py targets.txt Report")
        sys.exit(1)
    
    target_file = sys.argv[1]
    if len(sys.argv) >= 3:
        report_dir = sys.argv[2]
    else:
        report_dir = REPORT_DIR_DEFAULT

    scanner = EASMScanner(target_file, report_dir)
    scanner.run()


if __name__ == '__main__':
    main()
