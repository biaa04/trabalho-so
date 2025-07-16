import os
import time
import socket

def main():
    print(f"[*] Processo de teste PID={os.getpid()} executando syscalls...")
    time.sleep(40)
    
    with open("arquivo_teste.txt", "w") as f:
        f.write("linha 1\nlinha 2\n")

    with open("arquivo_teste.txt", "r") as f:
        f.read()

    try:
        s = socket.socket()
        s.connect(("example.com", 80))
    except:
        pass
    finally:
        s.close()

    time.sleep(2)

if __name__ == "__main__":
    main()
