import scapy
from scapy.all import *
import requests
import json
import time
import threading
import sys
import subprocess
import os
import csv
import ipaddress

url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

#unchanging IP list
all_ips=[]
#IP list to pop for VirusTotal
ip2chk=[]
#confirmed VT malicious IPs based on average >50% malicious detection
malicious_ip=[]

def chk_ip():
   while True:
      time.sleep(16)
      try:
         a=ip2chk.pop(0)
         print('sending to virustotal: ',a)
         params = {'apikey':'4e4cdb2c54f06ed3e83bd670c6374dad0fb22a6200753e50f9e713df1be466f5','ip':a}
         response=requests.get(url, params=params)
         json_response=response.json()
         dl_posi=[]
         for i in range(len(json_response['detected_urls'])):
            dl_posi.append(json_response['detected_urls'][i]['positives']/json_response['detected_urls'][i]['total']*100)
         dl_posi=int(sum(dl_posi))
         chk_res=dl_posi/len(json_response['detected_urls'])
         if chk_res > 50:
            malicious_ip.append(a)
            print('Malicious IP:',a,'with average',chk_res,'detection')
         else:
            print('Non-malicious IP:',a,'with average',chk_res,'detection')
      except KeyError:
         print('KeyError')
         pass
      except ZeroDivisionError:
         print('ZeroDivisonError')
         pass
      except IndexError:
         print('IndexError')
         pass
      except json.decoder.JSONDecodeError:
         print('Too many attempts')
         pass

#grab destination IP & check if already in unchanging IP list
def pkt_snif(pkt):
   try:
      a = ipaddress.ip_address(pkt[IP].dst).is_private
      if a is not True:
         if pkt[IP].dst not in all_ips:
            all_ips.append(pkt[IP].dst)
            ip2chk.append(pkt[IP].dst)
            print('Adding',pkt[IP].dst)
   except Exception:
      pass

#scapy packet sniffer function
def PKTscan():
   while True:
      sniff(prn=pkt_snif)


#query osquery tables processes and process_open_sockets
def pskiller():
   while True:
      time.sleep(5)
      proc=subprocess.Popen(["C:\\ProgramData\\osquery\\osqueryi.exe","--csv","select processes.pid,processes.name,process_open_sockets.remote_address,process_open_sockets.remote_port from process_open_sockets LEFT JOIN processes ON process_open_sockets.pid = processes.pid WHERE process_open_sockets.remote_port != 0 AND processes.name != '';"],stdout=subprocess.PIPE)
      stdout, stderr = proc.communicate()
      reader=csv.DictReader(stdout.decode('ascii').splitlines(),delimiter='|',skipinitialspace=True,fieldnames=['pid','name','ip'])
      #match malicious ip list to query results and kill related process
      for i in reader:
         for i['ip'] in malicious_ip:
            print('killing process',i['name'],i['pid'])
            temp= "taskkill /F /PID %s" % (i['pid'])
            #psexec \\hostname os.system(temp)
            os.system(temp)
      #os.system("taskkill /F /PID pkill")

thread1=threading.Thread(target=PKTscan)
thread2=threading.Thread(target=chk_ip)
thread3=threading.Thread(target=pskiller)
thread1.start()
thread2.start()
thread3.start()
