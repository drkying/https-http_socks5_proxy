import socket
import threading
import logging
import select

server_host = '127.0.0.1'
max_client_num = 1024
RSV = 0
BUF_SIZE = 1024
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


def b2ip(ATYP, data):  # 将请求中的ip或域名转换为字符串
    dst_port = -1
    dst_host = ''
    if ATYP == 3:  # 域名地址
        dst_len = ord(data[4:5])
        dst_port = 256 * ord(data[5 + dst_len:5 + dst_len + 1]) + ord(data[1 + 5 + dst_len:5 + dst_len + 2])
        dst_host = socket.gethostbyname(data[5:5 + dst_len])
    elif ATYP == 1:  # ipv4地址
        count = 0
        for i in data:
            if i is '.':
                count = count + 1
        if count == 3:  # 检查ip地址为'xx.xx.xx.xx'形式
            dst_len = ord(data[4:5])
            dst_host = data[5:5 + dst_len]
            dst_port = 256 * ord(data[5 + dst_len:5 + dst_len + 1]) + ord(data[5 + dst_len + 1:5 + dst_len + 2])
        else:  # 四个十六进制数表示ip
            dst_host = data[4:8]
            dst_ip = ''
            for i in dst_host:
                dst_ip += str(int(i)) + '.'
            dst_host = dst_ip[:-1]
            dst_port = 256 * ord(data[4 + 4:4 + 4 + 1]) + ord(data[4 + 4 + 1:4 + 4 + 2])
    else:
        logging.warning('IPV6 is not supported')
    return dst_host, dst_port


def proxy(connection, src_host):
    global dst_host, dst_port
    try:
        request1 = connection.recv(BUF_SIZE)
        respond = b'\x05\x00'
        connection.sendall(respond)
    except Exception:
        logging.warning("receive request from client error!")
        connection.close()
        return
    try:
        data = connection.recv(BUF_SIZE)
    except Exception:
        logging.warning("closed")
        connection.close()
        return
    try:
        CMD = ord(data[1:2])
        ATYP = ord(data[3:4])
        if CMD == 1:  # CONNECT类型的请求
            dst_host, dst_port = b2ip(ATYP, data)  # 获取请求中的ip或域名
        res = b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        connection.sendall(res)
        forward(connection, dst_host, dst_port)  # 开始转发请求
    except Exception:
        connection.close()
        return


def forward(connection, dst_host, dst_port):  # 转发请求数据
    try:
        server2dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server2dst.connect((dst_host, dst_port))  # 与目标服务器建立连接

    except Exception:
        logging.warning('CONNECT to', dst_host, 'failed')
    socks = [connection, server2dst]
    while True:
        r, w, e = select.select(socks, [], [])
        for s in r:
            if s is connection:
                recv = connection.recv(2048)  # 代理接收发送的请求并发送给目标服务器
                pass
                if recv.find(b"Host") >= 0:  # 判断链接协议为http时，对发送的请求进行修改
                    change(recv, 0)
                    print(recv.decode(errors="ignore"))
                caddr, cport = connection.getpeername()
                if (len(recv) > 0):
                    saddr, sport = server2dst.getpeername()
                    print(caddr, ':', cport, '->', saddr, ':', sport)
                    server2dst.send(recv)
                else:
                    for sock in socks:
                        sock.close()
                    return
            elif s is server2dst:
                recv = server2dst.recv(2048)  # 代理从目标服务器接收数据后转发给客户端
                if recv.find(b"Host") >= 0:
                    print(recv.decode(errors="ignore"))
                saddr, sport = server2dst.getpeername()
                if (len(recv) > 0):
                    caddr, cport = connection.getpeername()
                    print(saddr, ':', sport, '->', caddr, ':', cport)
                    connection.send(recv)
                else:
                    for sock in socks:
                        sock.close()
                    return


def main(server_port=9090):
    logging.warning("socks5 proxy starting")
    socks5 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks5.bind((server_host, server_port))
    socks5.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks5.listen(max_client_num)
    while True:
        conn, src_host = socks5.accept()  # 与代理进行连接
        threading.Thread(target=proxy, args=(conn, src_host)).start()


if __name__ == '__main__':
    main()
