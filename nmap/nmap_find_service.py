#-*- coding=utf-8 -*-
import sys,re

def usage():
    print
    print '*'*70
    print '*'
    print '* USAGE: nmap_find_service.py <nmap_log.log> <lower_case_service>'
    print '*'
    print '*    eg: nmap_find_service.py 10.x.x.0/24.log ssh'
    print '*'
    print '*'*70
    print
    sys.exit(0)

def main():
    if len(sys.argv) != 3:
        usage()

    f = sys.argv[1]
    f_pwd = sys.path[0] + '\\' + f
    service = sys.argv[2]

    try:
        INPUT_FILE = open(f_pwd,'r')
    except:
        usage()

    content = INPUT_FILE.read()
    INPUT_FILE.close()

    OUTPUT_FILE = open(f+'_find_{}.log'.format(service),'w')

    #?=后向匹配但不消耗字符串
    HOST_UP_PATTERN = re.compile('(Nmap scan report for (\d+\.\d+\.\d+\.\d+)\nHost is up.*?(?=((\nNmap scan report)|(\n# Nmap done))))',re.S)
    HOST_UP = re.findall(HOST_UP_PATTERN,content)

    for y in HOST_UP:
        SERVICE_PATTERN = re.compile('(\d+)\/tcp[ ]+open[ ]+(.*?)[ ]+(.*?)\n')
        SERVICE = re.findall(SERVICE_PATTERN,y[0])
        if SERVICE:
            for z in SERVICE:
                if service in z[2].lower():
                    print y[1] + ':' + z[0]
                    OUTPUT_FILE.write(y[1] + ':' + z[0] + '\n')
    OUTPUT_FILE.close()
    print 'Done!'

if __name__ == '__main__':
    main()