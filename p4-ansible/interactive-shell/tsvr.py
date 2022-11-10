import tftpy

if __name__ == "__main__":
    tsvr = tftpy.TftpServer('/tftpboot')
    tsvr.listen('192.168.52.161', 69)

