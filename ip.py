from iputils import *
import ipaddress


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
        self.identificador = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, \
                    checksum, src_addr, dest_addr = \
                    struct.unpack('!BBHHHBBHII', datagrama[:20])
            ttl -= 1
            if ttl != 0:
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, 0, src_addr, dest_addr)
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, calc_checksum(datagrama), src_addr, dest_addr)
            else:
                ttl = 64
                icmp_type = 11
                icmp_code = 0
                unused = 0
                payload = struct.pack('!BBHI', icmp_type, icmp_code, 0, unused) + datagrama[:28]
                payload = struct.pack('!BBHI', icmp_type, icmp_code, calc_checksum(payload), unused) + datagrama[:28]
                datagrama = struct.pack('!BBHHHBBH', vihl, dscpecn, 20 + len(payload), identification, flagsfrag, ttl, IPPROTO_ICMP, 0) + str2addr(self.meu_endereco) + str2addr('1.2.3.4')
                datagrama = struct.pack('!BBHHHBBH', vihl, dscpecn, 20 + len(payload), identification, flagsfrag, ttl, IPPROTO_ICMP, calc_checksum(datagrama)) + str2addr(self.meu_endereco) + str2addr('1.2.3.4')
            self.enlace.enviar(datagrama + payload, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        
        maior = -1
        content_to_return = None
        for content in self.tabela:
            if ipaddress.ip_address(dest_addr) in ipaddress.ip_network(content[0]):
                str_prefix = str(ipaddress.ip_network(content[0]))
                actual_prefix_number = int(str_prefix.split("/")[1])
                actual_content = content[1]
    
                if actual_prefix_number > maior:
                    maior = actual_prefix_number
                    content_to_return = actual_content
                
        return content_to_return

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
        self.tabela = tabela
        

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
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o datagrama com o cabeçalho IP, contendo como payload o segmento.

        vihl = 69
        dscpecn = 000
        total_len = 20 + len(segmento)
        identification = self.identificador
        flagsfrag = 00
        ttl = 64
        proto = IPPROTO_TCP
        checksum = 0
        pack = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum) + str2addr(self.meu_endereco) + str2addr(dest_addr)
        checksum = calc_checksum(pack)
        #print(checksum)
        datagrama = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum) + str2addr(self.meu_endereco) + str2addr(dest_addr) + segmento
        #print(datagrama)
        #print(segmento)
        self.identificador += 1
        self.enlace.enviar(datagrama, next_hop)
