from iputils import *
import socket
TTL = 64
TAM_MAX = 20


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def str2addr_int(str):

    return int(struct.unpack('!I', str2addr(str))[0])

def str2int(str):
    
    return int(str)

def calculo_desempate(ip,mask):

    return ( (ip // (2**(32-mask))) * (2**(32-mask)))

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = dict()
        self.contador = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)


        else:
            # atua como roteador

            msg_enviada = datagrama[:TAM_MAX]
            vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto,checksum, src_addr, dest_addr = struct.unpack('!BBHHHBBHII', msg_enviada)
            ttl -= 1 #Decrementar o ttl

            if ttl != 0: #não descartar o ttl

                next_hop = self._next_hop(dst_addr)

                check_sum = calc_checksum(struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto,0, src_addr, dest_addr))

                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto,check_sum ,src_addr, dest_addr)
                self.enlace.enviar(datagrama + payload, next_hop)

            else:
                
                my_addr = str2addr_int(self.meu_endereco)
                ip_binary  = int2ip(src_addr)

                next_hop = self._next_hop(ip_binary)

                type = 11
                code = 0
                rest = datagrama[:TAM_MAX+8]

                payload = struct.pack('!BBHi', type, code, 0, code)  + rest
                check_sum_ = calc_checksum(payload)
                payload = struct.pack('!BBHi', type, code, check_sum_, code) + rest

                check_sum = calc_checksum(struct.pack('!BBHHHBBHII', vihl, dscpecn, TAM_MAX + len(payload), identification, flagsfrag, TTL, IPPROTO_ICMP,0, my_addr, src_addr))
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, TAM_MAX + len(payload), identification, flagsfrag, TTL, IPPROTO_ICMP,check_sum, my_addr, src_addr)
                


                self.enlace.enviar(datagrama + payload, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        ip_binary = str2addr_int(dest_addr)
        for mask in range(32, -1, -1):
            if mask in self.tabela:
                
                ip_desempate = calculo_desempate(ip_binary,mask)

                if ip_desempate in self.tabela[mask]:
                    return self.tabela[mask][ip_desempate]
   
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = dict()
        dicionario_aux = dict()
        
        for cidr, next_hop in tabela:
            #Retirar /n
            stringuda = cidr.split('/')

            ip = stringuda[0]
            mask = str2int(stringuda[1])

            ip_binary = str2addr_int(ip) 

            dicionario_aux[ip_binary] = next_hop
            self.tabela[mask] = dicionario_aux
        
    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        vihl = 0x45 
        self.contador += 1
        identification = self.contador
        ttl = TTL
        


        datagrama = struct.pack('!BBHHHBBH', vihl, 0, TAM_MAX + len(segmento), 
            identification, 0, ttl, IPPROTO_TCP, 0) +  str2addr(self.meu_endereco) + str2addr(dest_addr)
        
        checksum = calc_checksum(datagrama)

        datagrama = struct.pack('!BBHHHBBH', vihl, 0, TAM_MAX + len(segmento), 
            identification, 0, ttl, IPPROTO_TCP, checksum) + str2addr(self.meu_endereco) + str2addr(dest_addr) + segmento
        
        self.enlace.enviar(datagrama, next_hop)