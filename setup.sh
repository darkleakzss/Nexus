#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

print_msg() {
	echo -e "${2}$1${NC}"
}

clear

echo -e "${RED}"
echo "=========================================="
echo "           INSTALLATION"
echo "=========================================="
echo -e "${NC}"

if [[ $EUID -eq 0 ]]; then
	print_msg "[+] Ejecutando como root" "$GREEN"
	SUDO=""
	else
		print_msg "[!] Ejecutando como usuario normal" "$YELLOW"
		print_msg "[!] Algunas instalaciones requieren sudo" "$YELLOW"
		SUDO="sudo"
		fi

		print_msg "[1] Verificando Python..." "$BLUE"
		
		if command -v python3 &> /dev/null; then
			PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
			print_msg "[+] Python $PY_VERSION ya instalado" "$GREEN"
			else
				print_msg "[-] Python3 no encontrado. Instalando..." "$YELLOW"
				
				if [ -f /etc/os-release ]; then
					. /etc/os-release
					OS=$ID
					else
						OS=$(uname -s)
						fi
						
						case $OS in
						ubuntu|debian|kali|linuxmint)
						$SUDO apt update
						$SUDO apt install -y python3 python3-pip
						;;
					fedora|centos|rhel)
					$SUDO dnf install -y python3 python3-pip
					;;
					arch|manjaro)
					$SUDO pacman -Sy python python-pip --noconfirm
					;;
					*)
					print_msg "[!] Sistema no soportado: $OS" "$RED"
					print_msg "[!] Instala Python3 manualmente" "$RED"
					exit 1
					;;
					esac
					
					if command -v python3 &> /dev/null; then
						print_msg "[+] Python3 instalado correctamente" "$GREEN"
						else
							print_msg "[!] Error instalando Python3" "$RED"
							exit 1
							fi
							fi
							

							print_msg "[2] Verificando Nmap..." "$BLUE"
							
							if command -v nmap &> /dev/null; then
								NMAP_VERSION=$(nmap --version 2>&1 | grep "Nmap version" | awk '{print $3}' | head -1)
								print_msg "[+] Nmap $NMAP_VERSION ya instalado" "$GREEN"
								else
									print_msg "[-] Nmap no encontrado. Instalando..." "$YELLOW"
									
									case $OS in
									ubuntu|debian|kali|linuxmint)
									$SUDO apt install -y nmap
									;;
								fedora|centos|rhel)
								$SUDO dnf install -y nmap
								;;
								arch|manjaro)
								$SUDO pacman -Sy nmap --noconfirm
								;;
								*)
								print_msg "[!] Instala Nmap manualmente desde: https://nmap.org" "$RED"
								;;
								esac
								
								if command -v nmap &> /dev/null; then
									print_msg "[+] Nmap instalado correctamente" "$GREEN"
									else
										print_msg "[!] Nmap no se pudo instalar" "$YELLOW"
										print_msg "[!] Algunas funciones no estarán disponibles" "$YELLOW"
										fi
										fi
										

										print_msg "[3] Verificando WHOIS..." "$BLUE"
										
										if command -v whois &> /dev/null; then
											print_msg "[+] WHOIS ya instalado" "$GREEN"
											else
												print_msg "[-] WHOIS no encontrado (opcional)" "$YELLOW"
												
												echo -n "¿Instalar WHOIS? (s/n): "
												read -r respuesta
												
												if [[ "$respuesta" =~ ^[SsYy] ]]; then
													case $OS in
													ubuntu|debian|kali|linuxmint)
													$SUDO apt install -y whois
													;;
												fedora|centos|rhel)
												$SUDO dnf install -y whois
												;;
												arch|manjaro)
												$SUDO pacman -Sy whois --noconfirm
												;;
												esac
												
												if command -v whois &> /dev/null; then
													print_msg "[+] WHOIS instalado" "$GREEN"
													fi
													fi
													fi

													print_msg "[4] Creando directorios..." "$BLUE"
													
													if [ ! -d "scan_results" ]; then
														mkdir -p scan_results
														mkdir -p scan_results/scripts_info
														print_msg "[+] Directorios creados: scan_results/" "$GREEN"
														else
															print_msg "[+] Directorios ya existen" "$GREEN"
															fi
															
											
															print_msg "[5] Verificando python.py..." "$BLUE"
															
															if [ -f "python.py" ]; then
																chmod +x python.py
																print_msg "[+] python.py encontrado y hecho ejecutable" "$GREEN"
																
																if ! head -1 python.py | grep -q "python3"; then
																	print_msg "[!] Añadiendo shebang a python.py..." "$YELLOW"
																	if grep -q "^#!/usr/bin/env python3" python.py; then
																		print_msg "[+] Shebang ya existe" "$GREEN"
																		else
																			TEMP_FILE=$(mktemp)
																			echo "#!/usr/bin/env python3" > "$TEMP_FILE"
																			cat python.py >> "$TEMP_FILE"
																			mv "$TEMP_FILE" python.py
																			chmod +x python.py
																			print_msg "[+] Shebang añadido" "$GREEN"
																			fi
																			fi
																			else
																				print_msg "[!] ERROR: python.py no encontrado en este directorio" "$RED"
																				print_msg "[!] Coloca python.py en la misma carpeta que setup.sh" "$RED"
																				exit 1
																				fi
															
																				print_msg "[6] Scripts adicionales de Nmap..." "$BLUE"
																				
																				echo -n "¿Instalar scripts vulners.nse? (recomendado) (s/n): "
																				read -r respuesta_scripts
																				
																				if [[ "$respuesta_scripts" =~ ^[SsYy] ]]; then
																					print_msg "[-] Instalando vulners.nse..." "$YELLOW"
																					
																					if ! command -v git &> /dev/null; then
																						print_msg "[-] Git no encontrado. Instalando..." "$YELLOW"
																						case $OS in
																						ubuntu|debian|kali|linuxmint)
																						$SUDO apt install -y git
																						;;
																					fedora|centos|rhel)
																					$SUDO dnf install -y git
																					;;
																					arch|manjaro)
																					$SUDO pacman -Sy git --noconfirm
																					;;
																					esac
																					fi
																					
																					if command -v git &> /dev/null; then
																						if [ -d "/tmp/nmap-vulners" ]; then
																							rm -rf /tmp/nmap-vulners
																							fi
																							
																							git clone https://github.com/vulnersCom/nmap-vulners.git /tmp/nmap-vulners 2>/dev/null
																							
																							if [ -f "/tmp/nmap-vulners/vulners.nse" ]; then
																								$SUDO cp /tmp/nmap-vulners/vulners.nse /usr/share/nmap/scripts/ 2>/dev/null ||
																								$SUDO cp /tmp/nmap-vulners/vulners.nse /usr/local/share/nmap/scripts/ 2>/dev/null
																								
																								if command -v nmap &> /dev/null; then
																									$SUDO nmap --script-updatedb 2>/dev/null || true
																									fi
																									
																									print_msg "[+] vulners.nse instalado" "$GREEN"
																									rm -rf /tmp/nmap-vulners
																									else
																										print_msg "[!] No se pudo descargar vulners.nse" "$YELLOW"
																										fi
																										else
																											print_msg "[!] Git no disponible. Omitiendo..." "$YELLOW"
																											fi
																											fi
													
																											print_msg "[7] Verificación final..." "$BLUE"
																											
																											echo ""
																											print_msg "=== RESUMEN DE INSTALACIÓN ===" "$GREEN"
																											echo ""
																											
																											if command -v python3 &> /dev/null; then
																												print_msg "✓ Python3: INSTALADO" "$GREEN"
																												else
																													print_msg "✗ Python3: FALTA" "$RED"
																													fi
																													
																													if command -v nmap &> /dev/null; then
																														print_msg "✓ Nmap: INSTALADO" "$GREEN"
																														else
																															print_msg "✗ Nmap: FALTA" "$RED"
																															fi
																															
																															if command -v whois &> /dev/null; then
																																print_msg "✓ WHOIS: INSTALADO" "$GREEN"
																																else
																																	print_msg "✗ WHOIS: OPCIONAL" "$YELLOW"
																																	fi
																																	
																																	if [ -f "python.py" ]; then
																																		print_msg "✓ python.py: PRESENTE" "$GREEN"
																																		else
																																			print_msg "✗ python.py: FALTANTE" "$RED"
																																			fi
																																			
																																			if [ -d "scan_results" ]; then
																																				print_msg "✓ Directorios: CREADOS" "$GREEN"
																																				fi
																																				
																																				echo ""
																																				print_msg "==========================================" "$GREEN"
																																				print_msg "   INSTALACIÓN COMPLETADA" "$GREEN"
																																				print_msg "==========================================" "$GREEN"
																																				echo ""
															
																																				print_msg "PARA EJECUTAR EL PROGRAMA:" "$BLUE"
																																				echo ""
																																				print_msg "Método 1 (recomendado):" "$YELLOW"
																																				print_msg "  ./python.py" "$GREEN"
																																				echo ""
																																				print_msg "Método 2:" "$YELLOW"
																																				print_msg "  python3 python.py" "$GREEN"
																																				echo ""
																																				print_msg "Método 3 (como root para todos los scans):" "$YELLOW"
																																				print_msg "  sudo ./python.py" "$GREEN"
																																				echo ""
																																				
																																				print_msg "NOTAS IMPORTANTES:" "$BLUE"
																																				print_msg "• El programa guarda resultados en: scan_results/" "$YELLOW"
																																				print_msg "• Como usuario normal, algunos scans pueden estar limitados" "$YELLOW"
																																				print_msg "• Como root, tendrás acceso a todos los tipos de scan" "$YELLOW"
																																				echo ""
																																				
																																				print_msg "¡LISTO! Presiona Enter para salir..." "$GREEN"
																																				read -r
																																				
																																				clear
																																				exit 0
