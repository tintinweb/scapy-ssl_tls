#from scapy.all import *
import subprocess
import socket
import ssl
from multiprocessing import Process
import unittest
import time
import sys

'''
if not hasattr(unittest.TestCase, "assertIn"):
    """
    TODO: remove_me - superdirty py2.6 patch as assertIn is not in py2.6
    """
    def assertIn(self, a, b):
        if not a in b:
            raise Exception("%r not in %r" %(a, b))
    setattr(unittest.TestCase, "assertIn", assertIn)
'''

class PopenProcess(object):
    """
    subprocess.Popen wrapper
    """
    def __init__(self, target, args=(), cwd=None, shell=None, want_stdout=False, want_stderr=False):
        # optional stdout, stderr to prevent deadlocks
        self.pid = subprocess.Popen([target] + [str(a) for a in args], 
                                    cwd=cwd, shell=shell, 
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE if want_stdout else None,
                                    stderr=subprocess.PIPE if want_stderr else None)
        self.stdin = self.pid.stdin
        self.stdout = self.stderr = None

    def getReturnCode(self, input=None):
        self.stdout, self.stderr = self.pid.communicate(input=input)
        exit_code = self.pid.poll()
        self.pid = None
        return exit_code

    def kill(self):
        if self.pid:
            try:
                self.pid.terminate()
                self.pid.communicate()
                self.pid.kill()
            except OSError:
                pass
            self.pid = None
            
    def __del__(self):
        self.kill()

class ForkProcess(object):
    """
    multiprocessing.Process wrapper
    """
    def __init__(self, target, args=()):
        self.pid = Process(target=target, args=args)

    def kill(self):
        if self.pid:
            self.pid.terminate()
            self.pid = None

    def __del__(self):
        self.kill()


def pytls_serve(bind=('', 8443),
                certfile="../tests/files/openssl_1_0_1_f_server.pem",
                ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL"):
    """
    python tls http echo server implementation
    :param bind:
    :param certfile:
    :param ssl_version:
    :param ciphers:
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(bind)
    s.listen(1)
    while True:
        ssl_sock = None
        client_sock, addr = s.accept()
        try:
            ssl_sock = ssl.wrap_socket(client_sock,
                                       server_side=True,
                                       certfile=certfile,
                                       keyfile=certfile,
                                       ssl_version=ssl_version,
                                       ciphers=ciphers,)
            data = []
            chunk = ssl_sock.read()
            while chunk:
                data.apend(chunk)
                chunk = ssl_sock.read()
                if not chunk:
                    break
            # echo request
            head = "HTTP/1.1 200 OK\r\nContent-type: text/html\r\nX-SERVER: pytls\r\n\r\n"
            ssl_sock.write(head + ''.join(data))
        except Exception:
            pass
        finally:
            if ssl_sock is not None:
                ssl_sock.shutdown(socket.SHUT_RDWR)
                ssl_sock.close()

class PythonTlsServer(ForkProcess):
    """
    python.ssl
    """
    def __init__(self, target=pytls_serve, args=(('127.0.0.1',8443),
                                                 "../tests/files/openssl_1_0_1_f_server.pem",
                                                 ssl.PROTOCOL_TLSv1)):
        self.bind = args[0]
        self.args = args[1:]
        self.pid = Process(target=target, args=args)
        self.pid.start()

class PythonInterpreter(PopenProcess):

    def __init__(self, target, args=(), cwd=None, want_stderr=False, want_stdout=False):
        super(PythonInterpreter, self).__init__(sys.executable, 
                                                args=[target]+list(args), 
                                                cwd=cwd, want_stderr=want_stderr, want_stdout=want_stdout)

class OpenSslServer(PopenProcess):
    """
    OpenSSL s_server
    """
    def __init__(self, target="openssl", args=()):
        self.bind = args[0]
        self.args = args[1:]

        args = ["s_server",
                "-accept", "%d"%self.bind[1],
                "-cert", self.args[0],
                "-cipher", "ALL",
                "-www"]
        if len(self.args)>1:
            args += ["-dcert",self.args[1]]
        super(OpenSslServer, self).__init__(target=target, args=args)
        
class OpenSslClient(PopenProcess):
    """
    OpenSSL s_server
    """
    def __init__(self, target="openssl", args=(), want_stderr=False, want_stdout=False):
        self.target = args[:2]
        self.args = args[2:]
        super(OpenSslClient, self).__init__(target=target, args=["s_client",
                                                                 "-connect", "%s:%d"%self.target,
                                                                 "-cipher", "ALL",],
                                            want_stderr=want_stderr, want_stdout=want_stdout)
        

class JavaTlsServer(PopenProcess):
    """
    Java tls server
    """
    def __init__(self, target="java", args=(), cwd=None):
        self.bind = args[0]
        self.args = args[1:]
        super(JavaTlsServer, self).__init__(target=target, args=["-cp", ".",
                                                                 '-Djavax.net.ssl.trustStore="keys/scapy-ssl_tls.jks"',
                                                                 '-Djavax.net.debug=ssl',
                                                                 'JSSEDebuggingServer'],
                                            cwd="../tests/integration/")


def wait_for_server(target):
    """
    wait for target to accept new connections
    :param target:
    :return:
    """
    last_exception = None
    timeout = time.time() + 20
    while time.time() < timeout:
        csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            csock.connect(target)
            last_exception = None
            print("server socket ready")
            break
        except socket.error as se:
            last_exception = se
        print("server socket not yet ready")
        time.sleep(0.5)
    csock.close()
    if last_exception:
        raise last_exception
    
def wait_for_bind_to_become_ready(bind):
    """
    wait for bind socket to become ready
    :param target:
    :return:
    """
    last_exception = None
    timeout = time.time() + 20
    while time.time() < timeout:
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ssock.bind(bind)
            last_exception = None
            print("server socket ready")
            break
        except socket.error as se:
            last_exception = se
        print("server socket not yet ready")
        time.sleep(0.5)
    ssock.close()
    if last_exception:
        raise last_exception
