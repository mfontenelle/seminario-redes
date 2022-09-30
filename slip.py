class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.fernandola = b'' # dados atuais
        self.sinal = False

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        # TODO: Preencha aqui com o código para enviar o datagrama pela linha
        # serial, fazendo corretamente a delimitação de quadros e o escape de
        # sequências especiais, de acordo com o protocolo CamadaEnlace (RFC 1055).
        data = b''

        for byte in datagrama:
            if byte.to_bytes(1, 'big') == b'\xC0':
                data += b'\xDB\xDC'
            elif byte.to_bytes(1, 'big') == b'\xDB':
                data += b'\xDB\xDD'
            else:
                data += byte.to_bytes(1, 'big')
                
        data = b'\xC0' + data + b'\xC0'
        self.linha_serial.enviar(data)

    def __raw_recv(self, dados):
        # TODO: Preencha aqui com o código para receber dados da linha serial.
        # Trate corretamente as sequências de escape. Quando ler um quadro
        # completo, repasse o datagrama contido nesse quadro para a camada
        # superior chamando self.callback. Cuidado pois o argumento dados pode
        # vir quebrado de várias formas difNoneerentes - por exemplo, podem vir
        # apenas pedaços de um quadro, ou um pedaço de quadro seguido de um
        # pedaço de outro, ou vários quadros de uma vez só.

        ferdinandinho = self.fernandola # conteudo recebido AGORA JA
        
        for byte in dados:
            if byte.to_bytes(1, 'big') == b'\xC0':
                if len(ferdinandinho) > 0:
                    try:
                        self.callback(ferdinandinho)
                    except:
                        import traceback
                        traceback.print_exc()
                    finally:
                        ferdinandinho = b''
                    
            elif byte.to_bytes(1, 'big') == b'\xDB':
                self.sinal = True

            elif self.sinal and byte.to_bytes(1, 'big') == b'\xDC':
                self.sinal = False
                ferdinandinho += b'\xC0'

            elif self.sinal and byte.to_bytes(1, 'big') == b'\xDD':
                self.sinal = False
                ferdinandinho += b'\xDB'

            else:
                ferdinandinho += byte.to_bytes(1, 'big')

        self.fernandola = ferdinandinho