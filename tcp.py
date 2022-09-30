import asyncio
from tcputils import *
import random
import time

TIMAO = 0.3
ALPHA = 0.125
BETA = 0.250

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            numero_sequencia = random.randint(1, 256)

            header = make_header(dst_port, src_port, numero_sequencia, seq_no + 1, FLAGS_SYN | FLAGS_ACK)
            header = fix_checksum(header, dst_addr, src_addr)

            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, numero_sequencia + 1, seq_no + len(payload) + 1)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.

            conexao.servidor.rede.enviar(header, src_addr)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, ack_atual, seq_esperado):
        self.ack_atual = ack_atual
        self.seq_esperado = seq_esperado
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = None  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida
        #self.timer = None
        self.content = b''
        self.fernandolas = b''
        self.tempos = {}
        self.rtt_estimado = None
        self.rtt_desviado = None
        self.intervalo_timeout = TIMAO
        self.cwnd = 1
        self.ultimo_ack_janela = ack_atual + MSS
        self.min_tam_janela = 1

    def intercala_timer(self):
        ## vai chamar `reenvia` com frequencia TIMAO ms
        if self.timer is not None:
            self.timer.cancel() 
        self.timer = asyncio.get_event_loop().call_later(self.intervalo_timeout, self.reenvia)

    def reenvia(self):
        print('Chamou `reenvia`')

        endereco_destino, porta_destino, endereco_fonte, porta_fonte = self.id_conexao
        dados = self.fernandolas[:MSS]

        if len(dados) == 0:
            print('len de dados em reenvia = 0')
            return

        header = make_header(porta_fonte, porta_destino, self.ack_atual, self.seq_esperado, FLAGS_ACK)
        header = fix_checksum(header + dados, endereco_fonte, endereco_destino)
        print('vai enviar')
        self.servidor.rede.enviar(header, endereco_destino)

        # O ack da janela deve ser dimminuido, caso haja necessidade de retransmissão
        self.ultimo_ack_janela -= (self.cwnd//2) * MSS

        #RightShift do  tamanho da janela comparado com o tamanho mínimo da janela
        if self.cwnd > 2:
            self.cwnd = self.cwnd//2
        else:
            self.cwnd = self.min_tam_janela

        carlinhos = self.ack_atual + len(dados)
        if carlinhos in self.tempos:
            del self.tempos[carlinhos]

        self.intercala_timer()

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        endereco_destino, porta_destino, endereco_fonte, porta_fonte = self.id_conexao

        if seq_no == self.seq_esperado:
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                header = make_header(porta_fonte, porta_destino, self.ack_atual, self.seq_esperado + 1, FLAGS_ACK)
                header = fix_checksum(header, endereco_fonte, endereco_destino)
                self.servidor.rede.enviar(header, endereco_destino)
                
                self.ack_atual = ack_no
                if self.callback:
                    self.callback(self, b'')

            else:
                header = make_header(porta_fonte, porta_destino, self.ack_atual, self.seq_esperado + len(payload), FLAGS_ACK)
                header = fix_checksum(header, endereco_fonte, endereco_destino)

                if len(payload) > 0:
                    self.seq_esperado += len(payload)
                    self.servidor.rede.enviar(header, endereco_destino)

                    if self.callback:
                        self.callback(self, payload)
                
                #Aumenta tamanho da janela. Caso o número de ack seja maior que o ack da janela, deve aumentar o ack
                if ack_no >= self.ultimo_ack_janela:
                    self.cwnd += 1
                
                if ack_no > self.ack_atual:
                    self.fernandolas = self.fernandolas[(ack_no - self.ack_atual):]
                    self.ack_atual = ack_no

                    if ack_no in self.tempos:
                        rtt = time.time() - self.tempos[ack_no]
                        print('dif', rtt)
                        if self.rtt_estimado is not None and self.rtt_desviado is not None:
                            self.rtt_estimado = (1-ALPHA) * self.rtt_estimado + ALPHA * rtt
                            self.rtt_desviado = (1-BETA) * self.rtt_desviado + BETA * abs(rtt - self.rtt_estimado)
                            self.intervalo_timeout = self.rtt_estimado + 4 * self.rtt_desviado

                        else:
                            self.rtt_estimado = rtt
                            self.rtt_desviado = rtt / 2
                            self.intervalo_timeout = self.rtt_estimado + 4 * self.rtt_desviado
                
                self.enviar2()

        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        print('recebido payload: %r' % payload)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        self.content += dados

        self.enviar2()

    def enviar2(self):
        """Nessa etapa, para enviar, caso não caiba na janela, deve-se enviar os dados separados, ou seja, envia uma parte por um header, e dps envia novamente 
        outro header com o restante da mensagem. O ultimo ack da janela seria o ack atual, após o envio da mensagem somado com o fernandolas( kkkkkk)
        """
        qntd_bytes = len(self.fernandolas)

        while qntd_bytes < self.cwnd * MSS:
            endereco_destino, porta_destino, endereco_fonte, porta_fonte = self.id_conexao

            jegue = self.content[:MSS]
            
            qntd_bytes += len(jegue)
            if len(jegue) == 0:
                break

            self.content = self.content[MSS:]

            header = make_header(porta_destino, porta_fonte, self.ack_atual + len(self.fernandolas), self.seq_esperado, FLAGS_ACK)

            self.fernandolas += jegue

            header = fix_checksum(header + jegue, endereco_fonte, endereco_destino)

            self.tempos[self.ack_atual + len(self.fernandolas)] = time.time()

            self.servidor.rede.enviar(header, endereco_destino)

            self.ultimo_ack_janela = self.ack_atual+len(self.fernandolas)

        self.intercala_timer()

    def fechar(self):
        endereco_destino, porta_destino, endereco_fonte, porta_fonte = self.id_conexao

        header = make_header(porta_fonte, porta_destino, self.ack_atual, self.seq_esperado + 1, FLAGS_FIN)
        header = fix_checksum(header, endereco_fonte, endereco_destino)
        self.servidor.rede.enviar(header, endereco_destino)