#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: IIS WebDav RCE
    info: CVE-2017-7269,Windows Server 2003R2版本IIS6.0的WebDAV服务中的ScStoragePathFromUrl函数存在缓存区溢出漏洞，
          远程攻击者通过以“If: <http://”开头的长header PROPFIND请求，执行任意代码，进而导致服务器被入侵控制。
    level: 紧急
    type: 远程溢出
    repair: 禁用 IIS 的 WebDAV 服务
'''

import socket
from POC_Framework import POC

class myPOC(POC):
    
    #单IP的POC
    def check(self, ip, port, timeout=5):
        try:
            socket.setdefaulttimeout(timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            payload = "OPTIONS / HTTP/1.0\r\n\r\n"
            s.send(payload) 
            data = s.recv(2048)
            s.close()
            if "PROPFIND" in data and "Microsoft-IIS/6.0" in data :
                return True
        except:
            return False

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()