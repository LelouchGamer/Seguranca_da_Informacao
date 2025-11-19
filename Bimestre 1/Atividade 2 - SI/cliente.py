#!/usr/bin/env python3
import asyncio
import json
import platform
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated # Importar eventos

class ChatClientProtocol(QuicConnectionProtocol):
    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    # Este método é chamado a cada evento QUIC, incluindo dados recebidos (Push Messages)
    def quic_event_received(self, event):
        super().quic_event_received(event)
        
        # O servidor está enviando dados em streams unidirecionais
        if isinstance(event, StreamDataReceived):
            # A leitura de streams no aioquic é baseada em buffer e offset
            # Como o servidor envia um JSON completo por stream e o fecha,
            # processamos os dados diretamente do evento.
            
            data = event.data
            
            if data:
                try:
                    # Tenta decodificar o JSON. Usamos strip() para remover o \n final
                    msg = json.loads(data.decode().strip())
                    
                    # --- Processamento da Mensagem ---
                    if msg.get("type") == "chat":
                        remetente = msg.get("remetente")
                        texto = msg.get("dados")
                        grupo = msg.get("grupo")
                        
                        # Imprime a mensagem e reexibe o prompt do usuário
                        if grupo:
                            print(f"\n[{grupo}] {remetente}: {texto}")
                        else:
                            print(f"\n{remetente}: {texto}")
                        print("> ", end="", flush=True) 
                        
                    elif msg.get("type") == "system":
                        print(f"\n[✔] {msg['msg']}")
                        print("> ", end="", flush=True) 
                    # --- Fim Processamento ---

                except json.JSONDecodeError:
                    # Ignora se o JSON for inválido/incompleto
                    pass
                except Exception as e:
                    print(f"\n[!] Erro ao processar mensagem recebida: {e}")

        elif isinstance(event, ConnectionTerminated):
             print("\n[!] Conexão QUIC encerrada pelo servidor.")


async def main():
    host = input("Host do servidor [padrao: 127.0.0.1]: ") or "127.0.0.1"
    user = input("Nome de usuario: ").strip()
    
    # Removemos o parâmetro server_name e verify_mode=False para aceitar o certificado local
    cfg = QuicConfiguration(is_client=True, verify_mode=False)

    print(f"\nConectando ao servidor {host}:4433...")
    
    try:
        async with connect(
            host, 4433,
            configuration=cfg,
            create_protocol=lambda *a, **kw: ChatClientProtocol(user, *a, **kw),
            wait_connected=True
        ) as proto:
            print("[✔] Conectado ao servidor QUIC com sucesso.")

            # 1. Registra usuário
            r, w = await proto.create_stream(is_unidirectional=True)
            w.write(json.dumps({"type": "register", "user": user}).encode() + b"\n")
            await w.drain()
            w.close()
            print(f"[✔] Registrado como {user}")

            # 2. Exibe comandos e inicia o loop de envio
            print("\nComandos disponiveis:")
            print("/msg <usuario> <mensagem>")
            print("/group <grupo> <mensagem>")
            print("/join <grupo>")
            print("/quit\n")

            while True:
                # Usa run_in_executor para tornar o input() não-bloqueante
                cmd = await asyncio.get_event_loop().run_in_executor(None, lambda: input("> ").strip())
                
                if not cmd:
                    continue
                
                # --- Encerramento ---
                if cmd.startswith("/quit"):
                    print("Encerrando cliente...")
                    break
                
                # --- Processamento de Comandos ---
                payload = None
                if cmd.startswith("/msg "):
                    try:
                        _, dest, *msg = cmd.split()
                        text = " ".join(msg)
                        payload = {"type": "chat", "remetente": user, "destino": dest, "dados": text}
                    except ValueError:
                        print("Uso: /msg <usuario> <mensagem>")
                        continue
                elif cmd.startswith("/group "):
                    try:
                        _, group, *msg = cmd.split()
                        text = " ".join(msg)
                        payload = {"type": "chat", "remetente": user, "grupo": group, "dados": text}
                    except ValueError:
                        print("Uso: /group <grupo> <mensagem>")
                        continue
                elif cmd.startswith("/join "):
                    try:
                        _, group = cmd.split()
                        payload = {"type": "join", "user": user, "grupo": group}
                    except ValueError:
                        print("Uso: /join <grupo>")
                        continue
                else:
                    print("Comando desconhecido.")
                    continue

                # --- Envio de Mensagem/Comando ---
                if payload:
                    r, w = await proto.create_stream(is_unidirectional=True)
                    w.write(json.dumps(payload).encode() + b"\n")
                    await w.drain()
                    w.close()
                    print("[→] Mensagem/Comando enviado")
            
    except ConnectionRefusedError:
        print(f"\n[!] Falha ao conectar. O servidor não está ativo em {host}:4433 ou o firewall está bloqueando o UDP.")
    except Exception as e:
        print(f"\n[!] Erro de conexão: {e}")


if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main())