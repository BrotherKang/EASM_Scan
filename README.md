# EASM_Scan
利用nmap對目標ip檢測是否有風險

原本是用來針對客戶對外服務的IP做簡單掃測的資安服務，
但為了有效統計及分析，所以Noel簡單寫了一個腳本可以做到：
1.外部攻擊面管理 (EASM) 巡檢報告：IP 曝險與異動分析
2.外部邊界資安合規性掃描與漏洞初步盤點
3.對外網路暴露風險檢視摘要
4.網際網路對外 IP 掃描巡檢報告
掃測時會讀入IP清單，結果會輸出為excle檔案。
後續接手後，做了些許調整

範例:
  # 標準掃描
  `python ip_scanner.py ip_list.txt`
  
  # 快速掃描
  `python ip_scanner.py ip_list.txt --mode quick --workers 10`
  
  # 完整掃描
  `python ip_scanner.py ip_list.txt --mode full --workers 3`
  
  # 關鍵服務掃描
  `python ip_scanner.py ip_list.txt --mode critical --workers 15`

  ip_lists.txt放目標清單的純文字檔
