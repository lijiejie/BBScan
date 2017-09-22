import urllib3
import socket
import struct
import logging
from urllib3.packages.six.moves.queue import Empty


urllib3.disable_warnings()
logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.CRITICAL)


class HTTPConnPool(urllib3.HTTPConnectionPool):
    def close(self):
        """
        Close all pooled connections and disable the pool.
        """
        # Disable access to the pool
        old_pool, self.pool = self.pool, None

        try:
            while True:
                conn = old_pool.get(block=False)
                if conn:
                    conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    conn.close()
        except Empty:
            pass


class HTTPSConnPool(urllib3.HTTPSConnectionPool):
    def close(self):
        """
        Close all pooled connections and disable the pool.
        """
        # Disable access to the pool
        old_pool, self.pool = self.pool, None

        try:
            while True:
                conn = old_pool.get(block=False)
                if conn:
                    conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    conn.close()
        except Empty:
            pass