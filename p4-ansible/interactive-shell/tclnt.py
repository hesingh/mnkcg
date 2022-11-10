import tftpy

if __name__ == "__main__":
    client = tftpy.TftpClient('192.168.52.161', 69)
    client.download('tna.bin', 'tna.bin')
