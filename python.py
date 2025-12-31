#!/usr/bin/env python3

import os
import subprocess
import sys
from datetime import datetime

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BRIGHT_RED = '\033[31;1m'
    BRIGHT_GREEN = '\033[32;1m'
    DARK_RED = '\033[31m'
    ORANGE = '\033[33m'
    LIGHT_GRAY = '\033[37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class NmapScanner:
    
    def __init__(self):
        self.target = None
        self.results_dir = "scan_results"
        self.scan_counter = 1
        self.script_dir = os.path.join(self.results_dir, "scripts_info")
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        self.clear_screen()
        banner = f"""
{Colors.BRIGHT_RED}{Colors.BOLD}
 __    __  ________  __    __  __    __   ______  
/  \  /  |/        |/  |  /  |/  |  /  | /      \ 
$$  \ $$ |$$$$$$$$/ $$ |  $$ |$$ |  $$ |/$$$$$$  |
$$$  \$$ |$$ |__    $$  \/$$/ $$ |  $$ |$$ \__$$/ 
$$$$  $$ |$$    |    $$  $$<  $$ |  $$ |$$      \ 
$$ $$ $$ |$$$$$/      $$$$  \ $$ |  $$ | $$$$$$  |
$$ |$$$$ |$$ |_____  $$ /$$  |$$ \__$$ |/  \__$$ |
$$ | $$$ |$$       |$$ |  $$ |$$    $$/ $$    $$/ 
$$/   $$/ $$$$$$$$/ $$/   $$/  $$$$$$/   $$$$$$/  
   TLG: @darkleakzss VPM                                               
{Colors.RESET}
{Colors.DARK_RED}{'=' * 60}{Colors.RESET}
{Colors.BRIGHT_RED}         NEXUS - SCAN {Colors.RESET}
{Colors.DARK_RED}{'=' * 60}{Colors.RESET}
{Colors.DARK_RED}      Una sociedad, una salvación.{Colors.RESET}
{Colors.DARK_RED}{'=' * 60}{Colors.RESET}
"""
        print(banner)
    
    def show_credits(self):
        self.clear_screen()
        self.display_banner()
        print(f"\n{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        self.print_colored("DONDE LOS ATAQUES SE ORIGINAN.", Colors.ORANGE)
        print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        
        self.print_colored("\n🔧 DESARROLLADO POR:", Colors.BRIGHT_RED)
        self.print_colored(" VPM", Colors.GREEN)
        
        self.print_colored("\n", Colors.BRIGHT_RED)
        self.print_colored("   Una sociedad, una salvación.", Colors.GREEN)
        
        self.print_colored("\n📜 FILOSOFÍA:", Colors.BRIGHT_RED)
        self.print_colored(" El giro de la era termino, ahora existe el empuje. ", Colors.GREEN)
        self.print_colored("   No dejamos que la historia nos defina, Nosotros definimos la historia con cada herramienta desarollada.", Colors.GREEN)
        self.print_colored("   Asi como hay una gran sociedad, hay una gran salvacion, a la cual nosotros llegaremos.", Colors.GREEN)
        self.print_colored("   Asi como hay una gran sociedad, hay una gran salvacion, a la cual nosotros llegaremos.", Colors.GREEN)

        self.print_colored("\n VERSIÓN: 2.0", Colors.BRIGHT_RED)
        self.print_colored("   HERRAMIENTA DISEÑADA PARA MIEMBROS DE NUESTRO EQUIPO. HERRAMIENTA PARA LA PRIMERA LINEA DE RESPUESTA, OEC SOCIETY.", Colors.GREEN)
        
        print(f"\n{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
    
    def print_colored(self, text, color=Colors.WHITE):
        print(f"{color}{text}{Colors.RESET}")
    
    def print_success(self, text):
        self.print_colored(f"[+] {text}", Colors.GREEN)
    
    def print_error(self, text):
        self.print_colored(f"[!] {text}", Colors.RED)
    
    def print_info(self, text):
        self.print_colored(f"[*] {text}", Colors.DARK_RED)
    
    def print_warning(self, text):
        self.print_colored(f"[!] {text}", Colors.RED)
    
    def print_nmap_output(self, text):
        print(f"{Colors.BRIGHT_GREEN}{text}{Colors.RESET}")
    
    def is_local_ip(self, ip):
        return ip.startswith("192.168.")
    
    def create_directories(self):
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
            self.print_success(f"Directorio '{self.results_dir}' creado")
        
        if not os.path.exists(self.script_dir):
            os.makedirs(self.script_dir)
            self.print_success(f"Directorio '{self.script_dir}' creado")
    
    def get_next_filename(self):
        while True:
            filename = f"scan{self.scan_counter}.txt"
            full_path = os.path.join(self.results_dir, filename)
            if not os.path.exists(full_path):
                return filename
            self.scan_counter += 1
    
    def save_results(self, results, custom_name=None):
        if custom_name:
            if not custom_name.endswith('.txt'):
                custom_name += '.txt'
            filename = custom_name
        else:
            filename = self.get_next_filename()
        
        full_path = os.path.join(self.results_dir, filename)
        
        try:
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(f"Scan realizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {self.target}\n")
                f.write("=" * 60 + "\n\n")
                f.write(results)
            
            self.print_success(f"Resultados guardados en: {full_path}")
            return full_path
        except Exception as e:
            self.print_error(f"Error al guardar archivo: {e}")
            return None
    
    def run_nmap_command(self, command):
        try:
            self.print_info(f"Ejecutando: {command}")
            self.print_info("Escaneo en progreso...")
            print(f"{Colors.DARK_RED}{'-' * 60}{Colors.RESET}")
            
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0:
                self.print_nmap_output(result.stdout)
                return result.stdout
            else:
                self.print_error(f"Error en nmap: {result.stderr}")
                return None
                
        except FileNotFoundError:
            self.print_error("Nmap no está instalado")
            return None
        except KeyboardInterrupt:
            self.print_warning("\nEscaneo interrumpido")
            return None
        except Exception as e:
            self.print_error(f"Error: {e}")
            return None
    
    def ping_check(self):
        self.clear_screen()
        self.display_banner()
        
        self.print_info(f"Verificando si {self.target} está activo...")
        print(f"{Colors.DARK_RED}{'-' * 60}{Colors.RESET}")
        
        if os.name == 'nt':
            command = f"ping -n 2 -w 1000 {self.target}"
        else:
            command = f"ping -c 2 -W 1 {self.target}"
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0:
                self.print_success(f"IP {self.target} ACTIVA - Respondiendo a ping")
                return True
            else:
                self.print_warning(f"IP {self.target} INACTIVA - No responde a ping")
                self.print_info("Usaremos -Pn en los scans")
                return False
                
        except Exception as e:
            self.print_error(f"Error al hacer ping: {e}")
            return False
    
    def normal_scan(self):
        if not self.ping_check():
            self.print_info("Continuando con escaneo usando -Pn (sin ping)")
        
        command = f"nmap -sn -Pn {self.target}"
        results = self.run_nmap_command(command)
        
        if results:
            if "host is up" in results.lower() or "Host is up" in results:
                self.print_success("Host detectado como activo")
            else:
                self.print_warning("Host no respondió al escaneo")
        
        return results
    
    def advanced_port_scan(self):
        self.clear_screen()
        self.display_banner()
        print(f"\n{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        self.print_colored("ESCANEOS AVANZADOS DE PUERTOS", Colors.ORANGE)
        self.print_colored("1. SYN Scan (Stealth)", Colors.GREEN)
        self.print_colored("2. TCP Connect Scan", Colors.GREEN)
        self.print_colored("3. UDP Scan", Colors.GREEN)
        self.print_colored("4. ACK Scan (firewall detection)", Colors.GREEN)
        self.print_colored("5. FIN Scan (evasión)", Colors.GREEN)
        self.print_colored("6. XMAS Scan", Colors.GREEN)
        self.print_colored("7. NULL Scan", Colors.GREEN)
        self.print_colored("8. IDLE Scan (zombie)", Colors.GREEN)
        print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        
        scan_type = input(f"\n{Colors.GREEN}Selecciona tipo (1-8): {Colors.RESET}").strip()
        
        print(f"\n{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        self.print_colored("OPCIONES DE PUERTOS:", Colors.ORANGE)
        self.print_colored("1. Puertos comunes (top 100)", Colors.GREEN)
        self.print_colored("2. Todos los puertos", Colors.GREEN)
        self.print_colored("3. Rangos específicos", Colors.GREEN)
        self.print_colored("4. Puertos específicos", Colors.GREEN)
        print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        
        port_choice = input(f"\n{Colors.GREEN}Selecciona opción (1-4): {Colors.RESET}").strip()
        
        scan_commands = {
            "1": "-sS",  # SYN 
            "2": "-sT",  # TCP 
            "3": "-sU",  # UDP 
            "4": "-sA",  # ACK 
            "5": "-sF",  # FIN 
            "6": "-sX",  # XMAS 
            "7": "-sN",  # NULL 
            "8": "-sI"   # IDLE 
        }
        
        base_cmd = scan_commands.get(scan_type, "-sS")
        
        if scan_type == "3":
            self.print_warning("ADVERTENCIA: Escaneo UDP puede ser muy lento")
        elif scan_type == "8":
            zombie = input(f"{Colors.GREEN}IP del zombie host: {Colors.RESET}").strip()
            base_cmd = f"-sI {zombie}"
        
        if port_choice == "1":
            command = f"nmap {base_cmd} -F -Pn {self.target}"
        elif port_choice == "2":
            command = f"nmap {base_cmd} -p- -Pn {self.target}"
            self.print_warning("ADVERTENCIA: Escaneo completo puede ser lento")
        elif port_choice == "3":
            ranges = input(f"{Colors.GREEN}Rangos (ej: 1-1000,2000-3000): {Colors.RESET}").strip()
            command = f"nmap {base_cmd} -p {ranges} -Pn {self.target}"
        elif port_choice == "4":
            ports = input(f"{Colors.GREEN}Puertos (ej: 22,80,443): {Colors.RESET}").strip()
            command = f"nmap {base_cmd} -p {ports} -Pn {self.target}"
        else:
            command = f"nmap {base_cmd} -F -Pn {self.target}"
        
        return self.run_nmap_command(command)
    
    def os_detection(self):
        self.clear_screen()
        self.display_banner()
        
        self.print_info("Detección de Sistema Operativo")
        self.print_info("Esta función intentará identificar el SO del target")
        print(f"{Colors.DARK_RED}{'-' * 60}{Colors.RESET}")
        
        print(f"\n{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        self.print_colored("OPCIONES OS DETECTION:", Colors.ORANGE)
        self.print_colored("1. OS Detection básico", Colors.GREEN)
        self.print_colored("2. OS Detection agresivo", Colors.GREEN)
        self.print_colored("3. OS Detection con versiones", Colors.GREEN)
        self.print_colored("4. OS Detection completo (A -T4)", Colors.GREEN)
        print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        
        choice = input(f"\n{Colors.GREEN}Selecciona opción (1-4): {Colors.RESET}").strip()
        
        if choice == "1":
            command = f"nmap -O -Pn {self.target}"
        elif choice == "2":
            command = f"nmap -O --osscan-guess -Pn {self.target}"
        elif choice == "3":
            command = f"nmap -O -sV -Pn {self.target}"
        elif choice == "4":
            command = f"nmap -A -T4 -Pn {self.target}"
        else:
            command = f"nmap -O -Pn {self.target}"
        
        self.print_warning("OS Detection requiere puertos abiertos")
        self.print_info("Ejecutando escaneo...")
        
        return self.run_nmap_command(command)
    
    def vulnerability_scan(self):
        self.clear_screen()
        self.display_banner()
        print(f"\n{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        self.print_colored("ESCANEOS DE VULNERABILIDAD", Colors.ORANGE)
        self.print_colored("1. Vulnerabilidades básicas", Colors.GREEN)
        self.print_colored("2. Scripts vuln completos", Colors.GREEN)
        self.print_colored("3. Escaneo agresivo", Colors.GREEN)
        self.print_colored("4. Por servicio específico", Colors.GREEN)
        print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        
        choice = input(f"\n{Colors.GREEN}Selecciona opción (1-4): {Colors.RESET}").strip()
        
        if choice == "1":
            command = f"nmap -sV --script vuln -Pn {self.target}"
        elif choice == "2":
            command = f"nmap -sV --script \"vuln and safe\" -Pn {self.target}"
        elif choice == "3":
            command = f"nmap -A -T4 --script vuln -Pn {self.target}"
        elif choice == "4":
            print(f"\n{Colors.YELLOW}Servicios disponibles:{Colors.RESET}")
            self.print_colored("1. HTTP/Web", Colors.GREEN)
            self.print_colored("2. SMB (Windows)", Colors.GREEN)
            self.print_colored("3. SSH", Colors.GREEN)
            self.print_colored("4. FTP", Colors.GREEN)
            self.print_colored("5. SSL/TLS", Colors.GREEN)
            vuln_choice = input(f"\n{Colors.GREEN}Servicio (1-5): {Colors.RESET}").strip()
            
            services = {
                "1": "http-*",
                "2": "smb-*",
                "3": "ssh-*",
                "4": "ftp-*",
                "5": "ssl-*"
            }
            
            service = services.get(vuln_choice, "http-*")
            command = f"nmap -sV --script \"{service} and vuln\" -Pn {self.target}"
        else:
            command = f"nmap -sV --script vuln -Pn {self.target}"
        
        return self.run_nmap_command(command)
    
    def script_scan(self):
        self.clear_screen()
        self.display_banner()
        print(f"\n{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        self.print_colored("ESCANEOS CON SCRIPTS", Colors.ORANGE)
        self.print_colored("1. Scripts básicos (-sC)", Colors.GREEN)
        self.print_colored("2. Scripts discovery", Colors.GREEN)
        self.print_colored("3. Scripts exploit", Colors.GREEN)
        self.print_colored("4. Scripts safe", Colors.GREEN)
        self.print_colored("5. Todos los scripts", Colors.GREEN)
        self.print_colored("6. Scripts por servicio", Colors.GREEN)
        print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        
        choice = input(f"\n{Colors.GREEN}Selecciona opción (1-6): {Colors.RESET}").strip()
        
        if choice == "1":
            command = f"nmap -sC -Pn {self.target}"
        elif choice == "2":
            command = f"nmap --script discovery -Pn {self.target}"
        elif choice == "3":
            command = f"nmap --script exploit -Pn {self.target}"
        elif choice == "4":
            command = f"nmap --script safe -Pn {self.target}"
        elif choice == "5":
            command = f"nmap --script all -Pn {self.target}"
        elif choice == "6":
            service = input(f"{Colors.GREEN}Servicio (ej: http, ftp, ssh): {Colors.RESET}").strip()
            command = f"nmap --script \"*{service}*\" -Pn {self.target}"
        else:
            command = f"nmap -sC -Pn {self.target}"
        
        return self.run_nmap_command(command)
    
    def whois_lookup(self):
        if self.is_local_ip(self.target):
            self.print_error("WHOIS no disponible para IPs locales")
            self.print_info("Intenta con una IP externa")
            input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
            return None
        
        command = f"whois {self.target}"
        self.print_info(f"Ejecutando: {command}")
        self.print_info("Obteniendo información WHOIS...")
        print(f"{Colors.DARK_RED}{'-' * 60}{Colors.RESET}")
        
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            if result.returncode == 0:
                self.print_nmap_output(result.stdout)
                return result.stdout
            else:
                self.print_info("Falló whois, intentando con nmap...")
                command = f"nmap --script whois-ip -Pn {self.target}"
                return self.run_nmap_command(command)
        except FileNotFoundError:
            self.print_warning("whois no está instalado")
            command = f"nmap --script whois-ip -Pn {self.target}"
            return self.run_nmap_command(command)
        except KeyboardInterrupt:
            self.print_warning("\nConsulta interrumpida")
            return None
    
    def show_scan_history(self):
        self.clear_screen()
        self.display_banner()
        
        if not os.path.exists(self.results_dir):
            self.print_warning("No hay escaneos guardados")
            input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
            return
        
        files = sorted([f for f in os.listdir(self.results_dir) if f.endswith('.txt')])
        
        if not files:
            self.print_warning("No hay escaneos guardados")
            input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
            return
        
        print(f"\n{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        self.print_colored("HISTORIAL DE ESCANEOS", Colors.ORANGE)
        print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        
        for i, file in enumerate(files, 1):
            file_path = os.path.join(self.results_dir, file)
            size = os.path.getsize(file_path)
            mod_time = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M')
            self.print_colored(f"{Colors.GREEN}{i}. {file}{Colors.RESET} - {size} bytes - {mod_time}", Colors.LIGHT_GRAY)
        
        print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
        choice = input(f"\n{Colors.GREEN}Ver archivo (número) o 0 para volver: {Colors.RESET}").strip()
        
        if choice == "0":
            return
        
        if choice.isdigit() and int(choice) > 0 and int(choice) <= len(files):
            selected_file = files[int(choice)-1]
            self.view_scan_file(selected_file)
        else:
            self.print_error("Opción inválida")
            input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
    
    def view_scan_file(self, filename):
        file_path = os.path.join(self.results_dir, filename)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.clear_screen()
            self.display_banner()
            
            print(f"\n{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
            self.print_colored(f"CONTENIDO: {filename}", Colors.ORANGE)
            print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
            self.print_nmap_output(content)
            print(f"{Colors.ORANGE}{'=' * 60}{Colors.RESET}")
            
            input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
        except Exception as e:
            self.print_error(f"Error al leer archivo: {e}")
            input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
    
    def get_target(self):
        self.clear_screen()
        self.display_banner()
        
        print(f"\n{Colors.DARK_RED}{'=' * 60}{Colors.RESET}")
        self.print_colored("IP Objetiva", Colors.BRIGHT_RED)
        print(f"{Colors.DARK_RED}{'=' * 60}{Colors.RESET}")
        
        while True:
            target = input(f"\n{Colors.GREEN}Ingresa el target (IP Victima): {Colors.RESET}").strip()
            
            if target:
                if (target.replace('.', '').replace('-', '').isalnum() or 
                    '.' in target or 
                    '-' in target):
                    self.target = target
                    self.print_success(f"Target establecido: {self.target}")
                    
                    if self.is_local_ip(self.target):
                        self.print_warning("Esta direccion es una IP local, dentro de tu red.")
                        self.print_info("Algunas funciones no estarán disponibles")
                        input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
                    
                    break
                else:
                    self.print_error("Objetivo invalido (IP)")
            else:
                self.print_error("No hay una direccion IP objetiva")
    
    def main_menu(self):
        while True:
            print(f"\n{Colors.DARK_RED}{'=' * 60}{Colors.RESET}")
            self.print_colored("NEXUS - NETSPLOITER", Colors.BRIGHT_RED)
            print(f"{Colors.DARK_RED}{'=' * 60}{Colors.RESET}")
            self.print_colored(f"Target actual: {self.target if self.target else 'No establecido'}", Colors.GREEN)
            print(f"\n{Colors.GREEN}Opciones disponibles:{Colors.RESET}")
            self.print_colored("1. Ping Check", Colors.GREEN)
            self.print_colored("2. Normal Scan", Colors.GREEN)
            self.print_colored("3. Advanced Port Scans", Colors.GREEN)
            self.print_colored("4. OS Detection", Colors.GREEN)
            self.print_colored("5. Vulnerability Scan", Colors.GREEN)
            self.print_colored("6. Script Scan", Colors.GREEN)
            self.print_colored("7. WHOIS Lookup", Colors.GREEN)
            self.print_colored("8. Créditos", Colors.GREEN)
            self.print_colored("9. Historial de escaneos", Colors.GREEN)
            self.print_colored("0. Cambiar target / Salir", Colors.GREEN)
            print(f"{Colors.DARK_RED}{'=' * 60}{Colors.RESET}")
            
            choice = input(f"\n{Colors.GREEN}Selecciona una opción (0-9): {Colors.RESET}").strip()
            
            if choice == "1":
                if self.target:
                    self.ping_check()
                    input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
                else:
                    self.print_error("Primero establece una IP")
            
            elif choice == "2":
                if self.target:
                    results = self.normal_scan()
                    if results:
                        self.ask_save_results(results)
                    input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
                else:
                    self.print_error("Primero establece una IP")
            
            elif choice == "3":
                if self.target:
                    results = self.advanced_port_scan()
                    if results:
                        self.ask_save_results(results)
                    input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
                else:
                    self.print_error("Primero establece un target")
            
            elif choice == "4":
                if self.target:
                    results = self.os_detection()
                    if results:
                        self.ask_save_results(results)
                    input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
                else:
                    self.print_error("Primero establece un target")
            
            elif choice == "5":
                if self.target:
                    results = self.vulnerability_scan()
                    if results:
                        self.ask_save_results(results)
                    input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
                else:
                    self.print_error("Primero establece un target")
            
            elif choice == "6":
                if self.target:
                    results = self.script_scan()
                    if results:
                        self.ask_save_results(results)
                    input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
                else:
                    self.print_error("Primero establece una IP")
            
            elif choice == "7":
                if self.target:
                    results = self.whois_lookup()
                    if results:
                        self.ask_save_results(results)
                    input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
                else:
                    self.print_error("Primero establece una IP")
            
            elif choice == "8":
                self.show_credits()
            
            elif choice == "9":
                self.show_scan_history()
            
            elif choice == "0":
                change = input(f"\n{Colors.GREEN}¿Cambiar target (c) o Salir (s)?: {Colors.RESET}").strip().lower()
                if change == 'c':
                    self.get_target()
                else:
                    self.clear_screen()
                    print(f"\n{Colors.GREEN}{'=' * 60}{Colors.RESET}")
                    self.print_success("Saliendo del programa...")
                    print(f"{Colors.GREEN}{'=' * 60}{Colors.RESET}")
                    break
            
            else:
                self.print_error("Opción inválida")
    
    def ask_save_results(self, results):
        save = input(f"\n{Colors.GREEN}¿Guardar resultados? (s/n): {Colors.RESET}").strip().lower()
        if save in ['s', 'si', 'yes', 'y']:
            custom_name = input(f"{Colors.GREEN}Nombre personalizado (vacío=auto): {Colors.RESET}").strip()
            if custom_name:
                self.save_results(results, custom_name)
            else:
                self.save_results(results)
        else:
            self.print_info("Resultados no guardados")
    
    def run(self):
        self.display_banner()
        self.create_directories()
        self.get_target()
        self.main_menu()

if __name__ == "__main__":
    try:
        scanner = NmapScanner()
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}Programa interrumpido{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error crítico: {e}{Colors.RESET}")
        sys.exit(1)
