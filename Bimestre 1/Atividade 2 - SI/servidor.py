#!/usr/bin/env python3
"""
Servidor QUIC de chat simples.
Gera cert.pem/key.pem automaticamente (com SAN localhost/127.0.0.1).
Use: python servidor.py
Digite 'stop' no terminal para encerrar.
"""
import asyncio
import json
import os
import ipaddress
import platform
from datetime import datetime, timedelta

from aioquic.asyncio import serve, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, StreamReset, ConnectionTerminated

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Variáveis Globais ---
USERS = {}
GROUPS = {}
PORT = 4433


def generate_certificates():
    if os.path.exists("cert.pem") and os.path.exists("key.pem"):
        return "cert.pem", "key.pem"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChatQUIC"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    alt_names = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(alt_names, critical=False)
        .sign(key, hashes.SHA256())
    )
    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Certificados gerados automaticamente com SAN: cert.pem e key.pem")
    return "cert.pem", "key.pem"


class ChatServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        # Mapeamento para buffers de streams para lidar com mensagens parciais
        self.stream_buffers = {}
        print("[*] Nova conexao QUIC aceita")

    # Função auxiliar para processar o JSON (registro, join, chat)
    async def _handle_stream_data(self, stream_id, data):
        try:
            # Usa strip() para remover o \n final
            msg = json.loads(data.decode().strip()) 
            tipo = msg.get("type")

            if tipo == "register":
                nome = msg.get("user")
                if nome:
                    self.user = nome
                    USERS[nome] = self
                    print(f"[+] Usuario registrado: {nome}")
                    # Envia confirmação (Push Message)
                    r, w = await self.create_stream(is_unidirectional=True)
                    w.write(json.dumps({"type": "system", "msg": f"Registrado: {nome}"}).encode() + b"\n")
                    await w.drain()
                    w.close()
                return

            if tipo == "join":
                user = msg.get("user")
                grupo = msg.get("grupo")
                if user and grupo:
                    GROUPS.setdefault(grupo, set()).add(user)
                    print(f"[+] {user} entrou no grupo {grupo}")
                return

            if tipo == "chat":
                remetente = msg.get("remetente")
                destino = msg.get("destino")
                texto = msg.get("dados")
                grupo = msg.get("grupo")

                # Lógica de chat em grupo
                if grupo:
                    membros = GROUPS.get(grupo, set())
                    print(f"[>] {remetente} enviou mensagem ao grupo {grupo}: {texto}")
                    for membro in membros:
                        if membro != remetente and membro in USERS:
                            proto = USERS[membro]
                            # Cria novo stream para Push Message
                            r_w, w_w = await proto.create_stream(is_unidirectional=True)
                            w_w.write(json.dumps({
                                "type": "chat",
                                "remetente": remetente,
                                "grupo": grupo,
                                "dados": texto
                            }).encode() + b"\n")
                            await w_w.drain()
                            w_w.close()

                # Lógica de chat privado
                elif destino:
                    if destino in USERS:
                        print(f"[>] {remetente} -> {destino}: {texto}")
                        proto = USERS[destino]
                        # Cria novo stream para Push Message
                        r_w, w_w = await proto.create_stream(is_unidirectional=True)
                        w_w.write(json.dumps({
                            "type": "chat",
                            "remetente": remetente,
                            "dados": texto
                        }).encode() + b"\n")
                        await w_w.drain()
                        w_w.close()
                return

        except json.JSONDecodeError:
            print(f"Erro JSON no stream {stream_id}: dados inválidos ou incompletos.")
        except Exception as e:
            print(f"Erro ao processar stream {stream_id}:", e)


    # Lida com eventos de conexão/streams (streams unidirecionais do cliente)
    def quic_event_received(self, event):
        super().quic_event_received(event)
        
        # Ajuste para evitar o uso de StreamDataReceived e StreamReset
        if isinstance(event, StreamDataReceived):
            # 1. Adiciona os dados ao buffer do stream
            current_data = self.stream_buffers.get(event.stream_id, b'') + event.data
            
            # 2. Verifica se recebemos o delimitador final (\n)
            if b'\n' in current_data:
                # Processa a primeira mensagem completa (assumindo uma por stream)
                asyncio.create_task(self._handle_stream_data(event.stream_id, current_data))
                
                # 3. Limpa o buffer desse stream após o processamento (Ajuste para versão antiga)
                if event.stream_id in self.stream_buffers:
                    del self.stream_buffers[event.stream_id]
                
            else:
                self.stream_buffers[event.stream_id] = current_data

        # Lida com desconexões
        if isinstance(event, (ConnectionTerminated, StreamReset)):
            if self.user and self.user in USERS:
                print(f"[-] Usuario desconectou: {self.user}")
                del USERS[self.user]
            
            # Limpa buffers de streams abertos
            self.stream_buffers.clear()

    # handle_stream removido (Não é usado para streams unidirecionais de comandos)
    def handle_stream(self, reader, writer):
        pass


async def main():
    certfile, keyfile = generate_certificates()
    cfg = QuicConfiguration(is_client=False)
    cfg.load_cert_chain(certfile, keyfile)
    print(f"Servidor QUIC ativo na porta {PORT}...")
    await serve("0.0.0.0", PORT, configuration=cfg, create_protocol=ChatServerProtocol)


if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    async def runner():
        task = asyncio.create_task(main())
        print("Digite 'stop' para encerrar o servidor.")
        while True:
            # Garante que o input não bloqueie o loop de eventos
            cmd = await asyncio.get_event_loop().run_in_executor(None, input)
            if cmd.strip().lower() in ("stop", "exit", "quit"):
                task.cancel()
                print("Encerrando servidor...")
                break
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(runner())