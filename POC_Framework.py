#!/usr/bin/env python
# -*- coding:utf-8 -*-

import socket,thread,datetime,time,sys,getopt,re,os,random

#漏洞检测框架
class POC():

    def __init__(self):
        return
    
    #WEB SERVER接受请求用
    def web_server(self):
        url_history = []
        self.web = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.web.bind(('0.0.0.0',8088))
        self.web.listen(10)
        while True:
            try:
                conn,addr = self.web.accept()
                data = conn.recv(4096)
                req_line = data.split("\r\n")[0]
                path = req_line.split()[1]
                #http://x.x.x.x:xx/add/yyy
                route_list = path.split('/')
                html = "NO"
                if len(route_list) == 3:
                    if route_list[1] == 'add':
                        if route_list[2] not in url_history:
                            url_history.append(route_list[2])
                    elif route_list[1] == 'check':
                        if route_list[2] in url_history:
                            url_history.remove(route_list[2])
                            html = 'YES'
                print datetime.datetime.now().strftime('%m-%d %H:%M:%S') + " " + str(addr[0]) +' web query: ' + path
                raw = "HTTP/1.0 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" %(len(html),html)
                conn.send(raw)
                conn.close()
            except:
                pass

    #启动线程
    def web_server_run(self):
        thread.start_new_thread(self.web_server(),())
        
    #POC
    def check(self):
        return

    #请求随机数
    def random_str(self,len):
        str1 = ''
        for i in range(len):
            str1 += (random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"))
        return str(str1)

    #获取本机IP
    def get_self_ip(self,ip):
        csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        csock.connect((ip, 80))
        (addr, port) = csock.getsockname()
        csock.close()
        return addr

    #获取检测对象列表 IP:PORT形式
    def get_target_ip_port(self):
        if len(sys.argv) < 3:
            self.usage()
        try:
            options,args = getopt.getopt(sys.argv[1:],'h:w:')
        except getopt.GetoptError:
            self.usage()

        for opt,arg in options:
            if opt == "-h":
                if not re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\:\d+$",arg):
                    self.usage()
                return [arg,]
            elif opt == "-w":
                if not os.path.isfile(arg):
                    self.usage()
                f = open(arg,'r')
                ipPort = []
                for x in f.readlines():
                    y = x.rstrip()
                    if not re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\:\d+$",y):
                        continue
                    ipPort.append(y)
                f.close()
                return ipPort
            else:
                self.usage()
            
    #结果文件
    def open_result_file(self):
        PATH = os.path.abspath(sys.path[0]) + '/log/'
        if not os.path.exists(PATH):
            os.makedirs(PATH)
        time = datetime.datetime.now().strftime('_%Y%m%d_%H_%M_%S')
        f_name = PATH + os.path.basename(sys.argv[0]) + time + '_result.log'
        f = open(f_name,'a')
        return f

    #执行任务
    def run(self):
        ipPortList = self.get_target_ip_port()
        f = self.open_result_file()
        i = 1
        j = 0
        l = len(ipPortList)
        print '[*]\n[*] Starting at {}\n'.format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        for ipPort in ipPortList:
            print 'Check {}/{} '.format(i,l),
            ip,port = ipPort.split(':')
            if self.check(ip,int(port)):
                f.write('[+] ' + ip + ':' + port + ' ---> [** vulnerability **]\n')
                print '[+] ' + ip + ':' + port + ' ---> [** vulnerability **]'
                j += 1
            else:
                print '[-] ' + ip + ':' + port + ' ---> [-* FAIL *-]'
            i += 1
        print '\n[*] Done at {}'.format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print '[!] Vulnerable Hosts: {}'.format(j)
        f.close()
    
    #使用提示
    def usage(self):
        print 
        print '*'*100
        print '*'
        print '* USAGE: <xxx_xxx.py> -h <ip>:<port>     eg.  {} -h 10.1.1.1:7001'.format(os.path.basename(sys.argv[0]))
        print '*'
        print '*    OR: <xxx_xxx.py> -w <ipPort File>   eg.  {} -w ip.txt'.format(os.path.basename(sys.argv[0]))
        print '*'
        print '*       <ipPort File>  -->  ip:port '
        print '*                           ip:port '
        print '*                           ip:port '
        print '*'
        print '*'*100
        print 
        sys.exit(0)

if __name__ == '__main__':
    
    print 
    print '*'*80
    print '*'
    print '* This is POC Framework!! DO NOT USE IT!!'
    print '*'
    print '*'
    print '* USAGE: <xxx_xxx.py> -h <ip>:<port>     eg.  weblogic_CVE_2015_4852.py -h 10.1.1.1:7001'
    print '*'
    print '*    OR: <xxx_xxx.py> -w <ipPort File>   eg.  weblogic_CVE_2015_4852.py -w ip.txt'
    print '*'
    print '*       <ipPort File>  -->  ip:port '
    print '*                           ip:port '
    print '*                           ip:port '
    print '*'
    print '*'*80
    print 
    sys.exit(0)