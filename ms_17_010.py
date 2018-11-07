#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: SMB远程溢出
    info: MS17-010（NSA Eternalblue SMB），攻击者可通过此漏洞执行任意代码，进而导致服务器被入侵控制。
    level: 紧急
    type: 远程溢出
    url: https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
    repair: 在所有网络和安全设备上封禁TCP 135 139 445端口，防止漏洞被各种蠕虫和病毒利用
            或在windows主机上使用防火墙屏蔽以上端口的入站访问
            补丁修复：在所有windows主机上安装MS17-010补丁
'''

import socket,binascii,struct
from POC_Framework import POC

class myPOC(POC):
    
    #单IP的POC
    def check(self, ip, port, timeout=5):
        NEGOTIATE_PROTOCOL_REQUEST = binascii.unhexlify("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
        SESSION_SETUP_REQUEST = binascii.unhexlify("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
        TREE_CONNECT_REQUEST = binascii.unhexlify("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
        NAMED_PIPE_TRANS_REQUEST = binascii.unhexlify("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(float(timeout) if timeout else None)
        s.connect((ip, port))

        # Send/receive negotiate protocol request
        s.send(NEGOTIATE_PROTOCOL_REQUEST)
        negotiate_reply = s.recv(1024)
        if len(negotiate_reply) < 36 or struct.unpack("<I", negotiate_reply[9:13])[0] != 0 :
            #print "[-] [%s] can't determine whether it's vulunerable" % ip
            return False

        # Send/receive session setup request
        s.send(SESSION_SETUP_REQUEST)
        session_setup_response = s.recv(1024)

        # Extract user ID from session setup response
        user_id = session_setup_response[32:34]

        os = ''
        word_count = ord(session_setup_response[36])
        if  word_count != 0: 
            # find byte count
            byte_count = struct.unpack("<H", session_setup_response[43:45])[0]
            if len(session_setup_response) != byte_count+45:
                #print_status("invalid session setup AndX response")
                pass
            else:
                # two continous null bytes indicate end of a unicode string
                for i in range(46, len(session_setup_response)-1):
                    if ord(session_setup_response[i]) == 0 and ord(session_setup_response[i+1]) == 0: 
                        # not necessary to support unicode
                        os = session_setup_response[46:i].decode("utf-8")
                        break

        # Replace user ID in tree connect request packet
        modified_tree_connect_request = list(TREE_CONNECT_REQUEST)
        modified_tree_connect_request[32] = user_id[0]
        modified_tree_connect_request[33] = user_id[1]
        modified_tree_connect_request = "".join(modified_tree_connect_request)

        # Send tree connect request
        s.send(modified_tree_connect_request)
        tree_connect_response = s.recv(1024)

        # Extract tree ID from response
        tree_id = tree_connect_response[28:30]

        # Replace tree ID and user ID in named pipe trans packet
        modified_trans2_session_setup = list(NAMED_PIPE_TRANS_REQUEST)
        modified_trans2_session_setup[28] = tree_id[0]
        modified_trans2_session_setup[29] = tree_id[1]
        modified_trans2_session_setup[32] = user_id[0]
        modified_trans2_session_setup[33] = user_id[1]
        modified_trans2_session_setup = "".join(modified_trans2_session_setup)

        # Send trans2 sessions setup request
        s.send(modified_trans2_session_setup)
        final_response = s.recv(1024)
        s.close()
        if final_response[9] == "\x05" and final_response[10] == "\x02" and final_response[11] == "\x00" and final_response[12] == "\xc0":
            #print "[+] [%s](%s) is likely VULNERABLE to MS17-010" % (ip, os)
            return True
        else:
            #print "[-] [%s](%s) stays in safety" % (ip, os)
            return False

if __name__ == '__main__':
    
    Check_POC = myPOC()
    Check_POC.run()