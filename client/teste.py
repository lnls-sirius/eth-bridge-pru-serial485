
#!/usr/bin/python3
# Rodar: python3 teste.py <NUMERO DE CICLOS>


import PRUserial485
import sys
import time

fbp_write_4setpoints = ['\x01','\x50','\x00','\x11','\x11']+['\x00']*16+['\x8d']
fbp_read_var_group = ["\x01", "\x12", "\x00", "\x01", "\x03", "\xe9"]

c = PRUserial485.EthBrigdeClient(ip_address='10.128.103.106')
c.threads_start()

# Limpa e cria grupo de variaveis
c.write(["\x01", "\x32", "\x00", "\x00", "\xcd"],1000)
c.write(includeChecksum(["\x01","\x30", "\x00", "\x0d", "\x19", "\x1a", "\x1b", "\x1c", "\x1d", "\x1e", "\x1f", "\x28", "\x2c", "\x30", "\x34", "\x38", "\x3c"]),1000)


t0 = time.time()
for i in range(int(sys.argv[1])):

    ini = time.time()
    a=c.write_then_read(fbp_write_4setpoints, 0)
    a=c.write_then_read(fbp_read_var_group, 0)
    fi = time.time()

    sys.stdout.write("{:.2f}\n".format((fi-ini)*1000))
    sys.stdout.flush()
tf = time.time()

sys.stdout.write("TEMPO TOTAL {:.1f} SEG\n".format(tf-t0))
sys.stdout.flush()



def includeChecksum(string):
    counter = 0
    i = 0
    while (i < len(string)):
        counter += ord(string[i])
        i += 1
    counter = (counter & 0xFF)
    counter = (256 - counter) & 0xFF
    return(string + [chr(counter)])
