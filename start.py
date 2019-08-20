import socket
import time
import threading
import socks5_1
import logging

BUFSIZE = 1024
port = 9090

Change_dict = {
    'User-Agent': 'Mozilla/5.0'
}


def change(data, sslflag=0):  # 修改http请求中的内容
    if sslflag == 0 and len(Change_dict) > 0:
        for block, content in Change_dict.items():
            index1 = data.find(block.encode("utf-8"))
            if index1 >= 0:
                index2 = data.find(b"\n", index1)
                if index2 >= 0:
                    content1 = data[index1 + len(block) + 2:index2 + 1]
                    content = content.encode() + b'\r\n'
                    data = data.replace(content1, content)
            else:
                logging.warning("No this data")
                return
    else:
        logging.warning("can't change ssl data")


def getIP(domain):  # 获取域名对应的ip地址
    myaddr = socket.getaddrinfo(domain, 'http')
    return myaddr[0][4][0]


class Access_to_Host(object):

    def handler(self, conn, addr):  # 开启代理
        self.conn = conn
        self.addr = addr
        all_src_data, hostname, port, ssl_flag = self.get_dst_host_from_header(self.conn, self.addr)  # 获取目标服务器的相关数据
        all_dst_data = self.get_data_from_host(hostname, port, all_src_data, ssl_flag)
        print("\n%s -> ('%s', %d)" % (str(addr), getIP(hostname), port))
        if all_dst_data and not ssl_flag:
            change(all_dst_data)
            self.ssl_client_server_client(self.conn, self.conn_dst, all_dst_data)
        elif ssl_flag:
            sample_data_to_client = b"HTTP/1.0 200 Connection Established\r\n\r\n"
            self.ssl_client_server_client(self.conn, self.conn_dst, sample_data_to_client)
        else:
            print('pls check network. cannot get hostname:' + hostname)

    def ssl_client_server(self, src_conn, dst_conn):
        self.src_conn = src_conn
        self.dst_conn = dst_conn
        while True:
            try:
                ssl_client_data = self.src_conn.recv(BUFSIZE)
            except Exception as e:
                print("client disconnect")
                print(e)
                self.src_conn.close()
                return False

            if ssl_client_data:
                try:
                    self.dst_conn.sendall(ssl_client_data)
                except Exception as e:
                    print("server disconnect Err")
                    self.dst_conn.close()
                    return False
            else:
                self.src_conn.close()
                return False

    def ssl_server_client(self, src_conn, dst_conn):
        self.src_conn = src_conn
        self.dst_conn = dst_conn

        while True:
            try:
                ssl_server_data = self.dst_conn.recv(BUFSIZE)
            except Exception as e:
                print("server disconnect ")
                self.dst_conn.close()
                return False

            if ssl_server_data:
                try:
                    self.src_conn.sendall(ssl_server_data)
                except Exception as e:
                    print("Client disconnect Err")
                    self.src_conn.close()
                    return False
            else:
                self.dst_conn.close()
                return False

    def ssl_client_server_client(self, src_conn, dst_conn, all_dst_data):
        self.src_conn = src_conn
        self.dst_conn = dst_conn
        try:
            self.src_conn.sendall(all_dst_data)
            print(all_dst_data.decode(errors="ignore"), end="\n")
        except Exception as e:
            print(e)
            print("cannot sent data(HTTP/1.0 200) to SSL client")
            return False
        threadlist = []

        t1 = threading.Thread(target=self.ssl_client_server, args=(self.src_conn, self.dst_conn))
        t2 = threading.Thread(target=self.ssl_server_client, args=(self.src_conn, self.dst_conn))
        threadlist.append(t1)
        threadlist.append(t2)
        for t in threadlist:
            t.start()
        while not self.dst_conn._closed:
            time.sleep(1)
        self.src_conn.close()

    def get_dst_host_from_header(self, conn_sock, addr):

        self.s_src = conn_sock
        self.addr = addr
        header = ""
        ssl_flag = False
        while True:
            header = self.s_src.recv(BUFSIZE)  # 代理接收客户机发送的请求
            if header:
                indexssl = header.split(b"\n")[0].find(b"CONNECT")  # 检查是否为https连接
                if indexssl > -1:
                    hostname = str(header.split(b"\n")[0].split(b":")[0].decode())
                    hostname = hostname[indexssl + 8:]
                    port = 443
                    ssl_flag = True
                    return header, hostname, port, ssl_flag  # 返回连接的相关数据
                index1 = header.find(b"Host:")
                index2 = header.find(b"GET http")
                index3 = header.find(b"POST http")
                if index1 > -1:
                    indexofn = header.find(b"\n", index1)
                    host = header[index1 + 5:indexofn]
                elif index2 > -1 or index3 > -1:
                    host = header.split(b"/")[2]
                else:  # 未获取到目标服务器的内容
                    print("src socket host:")
                    print(self.s_src.getpeername())
                    print("cannot find out host!!:" + repr(header))
                    return
                break
        host = str(host.decode().strip("\r").lstrip())
        if len(host.split(":")) == 2:  # 处理带端口的连接
            port = host.split(":")[1]
            hostname = host.split(":")[0].strip("")
        else:  # 不带端口的连接
            port = 80
            hostname = host.split(":")[0].strip("")
        ssl_flag = False
        return header, hostname, int(port), ssl_flag

    def get_data_from_host(self, host, port, sdata, ssl_flag):
        self.conn_dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        all_dst_data = ""
        try:
            self.conn_dst.connect((str(host), port))
        except Exception as e:
            print(e)
            print("get_data_from_host: cannot get host:" + host)
            self.conn_dst.close()
            return False
        try:
            if ssl_flag:
                return all_dst_data
            else:
                self.conn_dst.sendall(sdata)  # 对目标服务器发送http请求
        except Exception as e:
            print(e)
            print("cannot send data to host:" + host)
            self.conn_dst.close()
            return False
        # buffer=[]
        rc_data = self.conn_dst.recv(BUFSIZE)
        return rc_data


class Server(object):

    def Handle_Rec(conn_socket, addr):
        print("This is Handler Fun")
        pass

    def __init__(self, host, port):  # 初始化与代理的连接
        print("Server starting......")
        self.host = host
        self.port = port
        self.s_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s_s.bind((host, port))
        self.s_s.listen(1024)

    def start(self):
        while True:
            try:
                conn, addr = self.s_s.accept()  # 监听代理接收的连接并开始处理
                threading.Thread(target=Access_to_Host().handler, args=(conn, addr)).start()
            except Exception as e:
                print(str(e))
                print("\nExcept happend")


if __name__ == "__main__":
    a = int(input("1. " + 'http/https proxy' + '\n' + '2. ' + 'socks5 proxy\n'))
    if a == 1:
        host = '127.0.0.1'
        svr = Server(host, port)
        svr.start()
    else:
        socks5_1.main(port)
