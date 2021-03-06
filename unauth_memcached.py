#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: memcached未授权访问
    level: 中危
    type: 未授权访问
    repair: 1、如果为本机使用，仅监听127.0.0.1  
            2、memcached本身无认证机制，需使用主机防火墙来限制源IP地址的访问
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
            s.send("stats\r\n")
            result = s.recv(1024)
            if "STAT version" in result:
                return True
        except:
            return False

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()