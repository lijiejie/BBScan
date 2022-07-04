# @Author  : helit

import binascii
import asyncio
from lib.common import save_script_result

ports_to_check = 445


def get_tree_connect_request(ip, tree_id):
    ipc = "005c5c" + ip.encode().hex() + "5c49504324003f3f3f3f3f00"
    ipc_len_hex = hex(int(len(ipc) / 2)).replace("0x", "")
    smb = "ff534d4275000000001801280000000000000000000000000000729c" + tree_id.hex() + \
          "c4e104ff00000000000100" + ipc_len_hex + "00" + ipc
    tree = "000000" + hex(int(len(smb) / 2)).replace("0x", "") + smb
    tree_connect_request = binascii.unhexlify(tree)
    return tree_connect_request


async def do_check(self, url):
    if url != '/' or 445 not in self.ports_open:
        return

    ip = self.host.split(':')[0]
    port = 445

    negotiate_protocol_request = binascii.unhexlify(
        "00000054ff534d4272000000001801280000000000000000000000000000729c0000c4e1003100024c414e4d414e312e3000024c4d3"
        "12e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
    session_setup_request = binascii.unhexlify(
        "0000008fff534d4273000000001801280000000000000000000000000000729c0000c4e10cff000000dfff020001000000000031000"
        "0000000d400008054004e544c4d5353500001000000050208a2010001002000000010001000210000002e3431426c7441314e50597"
        "4624955473057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(negotiate_protocol_request)
        await writer.drain()
        await asyncio.wait_for(reader.read(1024), timeout=4)

        writer.write(session_setup_request)
        data = await asyncio.wait_for(reader.read(1024), timeout=4)
        user_id = data[32:34]

        session_setup_request_2 = binascii.unhexlify(
            "00000150ff534d4273000000001801280000000000000000000000000000729c" + user_id.hex() +
            "c4e10cff000000dfff0200010000000000f200000000005cd0008015014e544c4d535350000300000018001800"
            "40000000780078005800000002000200d000000000000000d200000020002000d200000000000000f20000000"
            "50208a2ec893eacfc70bba9afefe94ef78908d37597e0202fd6177c0dfa65ed233b731faf86b02110137dc50"
            "101000000000000004724eed7b8d2017597e0202fd6177c0000000002000a0056004b002d005000430001000a"
            "0056004b002d005000430004000a0056004b002d005000430003000a0056004b002d0050004300070008003"
            "6494bf1d7b8d20100000000000000002e003400310042006c007400410031004e005000590074006200490"
            "055004700300057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")

        writer.write(session_setup_request_2)
        await asyncio.wait_for(reader.read(1024), timeout=4)
        session_setup_request_3 = binascii.unhexlify(
            "00000063ff534d4273000000001801200000000000000000000000000000729c0000c4e10dff000000dfff020001000000000000"
            "00000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        writer.write(session_setup_request_3)
        data = await asyncio.wait_for(reader.read(1024), timeout=4)
        tree_id = data[32:34]
        smb = get_tree_connect_request(ip, tree_id)
        writer.write(smb)
        await asyncio.wait_for(reader.read(1024), timeout=4)
        poc = binascii.unhexlify(
            "0000004aff534d422500000000180128000000000000000000000000" + user_id.hex() + "729c" +
            tree_id.hex() + "c4e11000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
        writer.write(poc)
        data = await asyncio.wait_for(reader.read(1024), timeout=4)
        writer.close()
        try:
            await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass
        if b"\x05\x02\x00\xc0" in data:
            await save_script_result(self, '', ip + ':445', '', 'MS17010 SMB Remote Code Execution')
    except Exception as e:
        return False
