import sys
import os
import httplib
import time
import socket
import struct
import binascii

import OpenSSL
SSLError = OpenSSL.SSL.WantReadError

import socks
import check_local_network
from config import config
import cert_util
import openssl_wrap
import hyper

file_path = os.path.dirname(os.path.abspath(__file__))
current_path = os.path.abspath(os.path.join(file_path, os.pardir))
g_cacertfile = os.path.join(current_path, "cacert.pem")
openssl_context = openssl_wrap.SSLConnection.context_builder(ca_certs=g_cacertfile)
try:
    openssl_context.set_session_id(binascii.b2a_hex(os.urandom(10)))
except:
    pass

if hasattr(OpenSSL.SSL, 'SESS_CACHE_BOTH'):
    openssl_context.set_session_cache_mode(OpenSSL.SSL.SESS_CACHE_BOTH)

max_timeout = 5

default_socket = socket.socket


def load_proxy_config():
    global default_socket
    if config.PROXY_ENABLE:

        if config.PROXY_TYPE == "HTTP":
            proxy_type = socks.HTTP
        elif config.PROXY_TYPE == "SOCKS4":
            proxy_type = socks.SOCKS4
        elif config.PROXY_TYPE == "SOCKS5":
            proxy_type = socks.SOCKS5
        else:
            raise

        socks.set_default_proxy(proxy_type, config.PROXY_HOST, config.PROXY_PORT, config.PROXY_USER, config.PROXY_PASSWD)
load_proxy_config()


def connect_ssl(ip, port=443, timeout=5, check_cert=True):
    ip_port = (ip, port)

    if config.PROXY_ENABLE:
        sock = socks.socksocket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
    else:
        sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    # resize socket recv buffer 8K->32K to improve browser releated application performance
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
    sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
    sock.settimeout(timeout)

    ssl_sock = openssl_wrap.SSLConnection(openssl_context, sock, ip)
    ssl_sock.set_connect_state()

    time_begin = time.time()
    ssl_sock.connect(ip_port)
    time_connected = time.time()
    ssl_sock.do_handshake()

    try:
        h2 = ssl_sock.get_alpn_proto_negotiated()
        if h2 == "h2":
            ssl_sock.h2 = True
        else:
            ssl_sock.h2 = False
    except Exception as e:
        if hasattr(ssl_sock._connection, "protos") and ssl_sock._connection.protos == "h2":
            ssl_sock.h2 = True
        else:
            ssl_sock.h2 = False
    time_handshaked = time.time()

    # report network ok
    check_local_network.network_stat = "OK"
    check_local_network.last_check_time = time_handshaked
    check_local_network.continue_fail_count = 0

    cert = ssl_sock.get_peer_certificate()
    if not cert:
        raise socket.error(' certficate is none')

    if check_cert:
        issuer_commonname = next((v for k, v in cert.get_issuer().get_components() if k == 'CN'), '')
        if not issuer_commonname.startswith('Google'):
            raise socket.error(' certficate is issued by %r, not Google' % ( issuer_commonname))

    connct_time = int((time_connected - time_begin) * 1000)
    handshake_time = int((time_handshaked - time_connected) * 1000)

    # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
    ssl_sock._sock = sock
    ssl_sock.connct_time = connct_time
    ssl_sock.handshake_time = handshake_time

    return ssl_sock


def get_ssl_cert_domain(ssl_sock):
    cert = ssl_sock.get_peer_certificate()
    if not cert:
        raise SSLError("no cert")

    #issuer_commonname = next((v for k, v in cert.get_issuer().get_components() if k == 'CN'), '')
    ssl_cert = cert_util.SSLCert(cert)
    ssl_sock.domain = ssl_cert.cn


def check_goagent(ssl_sock, appid):
    request_data = 'GET /_gh/ HTTP/1.1\r\nHost: %s.appspot.com\r\n\r\n' % appid
    ssl_sock.send(request_data.encode())
    response = httplib.HTTPResponse(ssl_sock, buffering=True)

    response.begin()

    server_type = response.getheader('Server', "")
    if response.status == 404:
        return False

    if response.status == 503:
        # out of quota
        if "gws" not in server_type and "Google Frontend" not in server_type and "GFE" not in server_type:
            return False
        else:
            return True

    if response.status != 200:
        return False

    content = response.read()
    if "GoAgent" not in content:
        return False

    return True


def test_gae_ip2(ip, appid="xxnet-1"):
    try:
        ssl_sock = connect_ssl(ip, timeout=max_timeout)
        get_ssl_cert_domain(ssl_sock)
    except socket.timeout:
        return False
    except Exception as e:
        return False

    ssl_sock.support_gae = False
    if not ssl_sock.h2:

        try:
            if not check_goagent(ssl_sock, appid):
                return ssl_sock
            else:
                ssl_sock.support_gae = True
                return ssl_sock
        except Exception as e:
            return False

    try:
        conn = hyper.HTTP20Connection(ssl_sock, host='%s.appspot.com'%appid, ip=ip, port=443)
        conn.request('GET', '/_gh/')
    except Exception as e:
        return ssl_sock

    try:
        response = conn.get_response()
    except Exception as e:
        return ssl_sock

    if response.status == 404:
        return ssl_sock

    if response.status == 503:
        # out of quota
        server_type = response.headers.get('Server', "")
        if "gws" not in server_type and "Google Frontend" not in server_type and "GFE" not in server_type:
            return ssl_sock
        else:
            ssl_sock.support_gae = True
            return ssl_sock

    if response.status != 200:
        return ssl_sock

    content = response.read()
    if "GoAgent" not in content:
        return ssl_sock

    ssl_sock.support_gae = True
    return ssl_sock
