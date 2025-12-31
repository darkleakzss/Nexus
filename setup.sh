#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

print_msg() {
    echo -e "${2}$1${NC}"
}

clear

echo -e "${RED}"
echo "╔══════════════════════════════════════╗"
echo "║     FUCK3D YOUR IP - INSTALLER       ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

IS_TERMUX=false
if [ -d "/data/data/com.termux/files/usr" ]; then
    IS_TERMUX=true
    print_msg "[+] Detectado: Termux" "$GREEN"
fi

if [[ $EUID -eq 0 ]] && [ "$IS_TERMUX" = false ]; then
    print_msg "[+] Ejecutando como root" "$GREEN"
    SUDO=""
else
    if [ "$IS_TERMUX" = true ]; then
        print_msg "[+] Termux detectado, usando pkg" "$GREEN"
        SUDO=""
    else
        print_msg "[!] Usuario normal" "$YELLOW"
        SUDO="sudo"
    fi
fi

print_msg "[1] Actualizando sistema..." "$BLUE"

if [ "$IS_TERMUX" = true ]; then
    pkg update -y
    pkg upgrade -y
else
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        OS=$(uname -s)
    fi
    
    case $OS in
        ubuntu|debian|kali|linuxmint|parrot)
            $SUDO apt update -y
            $SUDO apt upgrade -y
            ;;
        fedora|centos|rhel)
            $SUDO dnf update -y
            ;;
        arch|manjaro)
            $SUDO pacman -Syu --noconfirm
            ;;
    esac
fi

print_msg "[2] Instalando Python3..." "$BLUE"

if command -v python3 &> /dev/null; then
    PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    print_msg "[+] Python $PY_VERSION ya instalado" "$GREEN"
else
    print_msg "[-] Instalando Python3..." "$YELLOW"
    
    if [ "$IS_TERMUX" = true ]; then
        pkg install python -y
    else
        case $OS in
            ubuntu|debian|kali|linuxmint|parrot)
                $SUDO apt install -y python3 python3-pip python3-venv
                ;;
            fedora|centos|rhel)
                $SUDO dnf install -y python3 python3-pip
                ;;
            arch|manjaro)
                $SUDO pacman -Sy python python-pip --noconfirm
                ;;
            *)
                print_msg "[!] Sistema no soportado: $OS" "$RED"
                exit 1
                ;;
        esac
    fi
    
    if command -v python3 &> /dev/null; then
        print_msg "[+] Python3 instalado" "$GREEN"
    else
        print_msg "[!] Error instalando Python3" "$RED"
        exit 1
    fi
fi

if [ "$IS_TERMUX" = true ]; then
    pip install --upgrade pip
else
    python3 -m pip install --upgrade pip
fi

print_msg "[3] Instalando Nmap..." "$BLUE"

if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version 2>&1 | grep "Nmap version" | awk '{print $3}' | head -1)
    print_msg "[+] Nmap $NMAP_VERSION ya instalado" "$GREEN"
else
    print_msg "[-] Instalando Nmap..." "$YELLOW"
    
    if [ "$IS_TERMUX" = true ]; then
        pkg install nmap -y
    else
        case $OS in
            ubuntu|debian|kali|linuxmint|parrot)
                $SUDO apt install -y nmap
                ;;
            fedora|centos|rhel)
                $SUDO dnf install -y nmap
                ;;
            arch|manjaro)
                $SUDO pacman -Sy nmap --noconfirm
                ;;
        esac
    fi
    
    if command -v nmap &> /dev/null; then
        print_msg "[+] Nmap instalado" "$GREEN"
    else
        print_msg "[!] Nmap no instalado" "$YELLOW"
    fi
fi

print_msg "[4] Instalando herramientas extras..." "$BLUE"

if [ "$IS_TERMUX" = true ]; then
    pkg install git -y
    pkg install wget -y
    pkg install curl -y
else
    case $OS in
        ubuntu|debian|kali|linuxmint|parrot)
            $SUDO apt install -y git wget curl whois
            ;;
        fedora|centos|rhel)
            $SUDO dnf install -y git wget curl whois
            ;;
        arch|manjaro)
            $SUDO pacman -Sy git wget curl whois --noconfirm
            ;;
    esac
fi

print_msg "[5] Creando directorios..." "$BLUE"

if [ ! -d "scan_results" ]; then
    mkdir -p scan_results
    mkdir -p scan_results/scripts_info
    print_msg "[+] Directorios creados" "$GREEN"
else
    print_msg "[+] Directorios ya existen" "$GREEN"
fi

print_msg "[6] Configurando python.py..." "$BLUE"

if [ -f "python.py" ]; then
    chmod +x python.py
    
    if ! head -1 python.py | grep -q "python3"; then
        TEMP_FILE=$(mktemp 2>/dev/null || echo "temp_python.py")
        echo "#!/usr/bin/env python3" > "$TEMP_FILE"
        cat python.py >> "$TEMP_FILE"
        mv "$TEMP_FILE" python.py
        chmod +x python.py
        print_msg "[+] Shebang añadido" "$GREEN"
    fi
    
    print_msg "[+] python.py listo" "$GREEN"
else
    print_msg "[!] ERROR: python.py no encontrado" "$RED"
    print_msg "[!] Coloca python.py aquí primero" "$RED"
    exit 1
fi

print_msg "[7] Instalando scripts Nmap extras..." "$BLUE"

echo -n "¿Instalar vulners.nse? (s/n): "
read -r respuesta_scripts

if [[ "$respuesta_scripts" =~ ^[SsYy] ]]; then
    print_msg "[-] Descargando vulners.nse..." "$YELLOW"
    
    if command -v git &> /dev/null; then
        if [ -d "/tmp/nmap-vulners" ]; then
            rm -rf /tmp/nmap-vulners
        fi
        
        git clone https://github.com/vulnersCom/nmap-vulners.git /tmp/nmap-vulners 2>/dev/null
        
        if [ -f "/tmp/nmap-vulners/vulners.nse" ]; then
            if [ "$IS_TERMUX" = true ]; then
                cp /tmp/nmap-vulners/vulners.nse $PREFIX/share/nmap/scripts/ 2>/dev/null || true
                nmap --script-updatedb 2>/dev/null || true
            else
                $SUDO cp /tmp/nmap-vulners/vulners.nse /usr/share/nmap/scripts/ 2>/dev/null ||
                $SUDO cp /tmp/nmap-vulners/vulners.nse /usr/local/share/nmap/scripts/ 2>/dev/null
                
                if command -v nmap &> /dev/null; then
                    $SUDO nmap --script-updatedb 2>/dev/null || true
                fi
            fi
            
            print_msg "[+] vulners.nse instalado" "$GREEN"
            rm -rf /tmp/nmap-vulners
        else
            print_msg "[!] Error descargando vulners.nse" "$YELLOW"
        fi
    else
        print_msg "[!] Git no disponible" "$YELLOW"
    fi
fi

print_msg "[8] Verificación final..." "$BLUE"

echo ""
print_msg "=== RESUMEN ===" "$PURPLE"
echo ""

if command -v python3 &> /dev/null; then
    print_msg "✓ Python3: INSTALADO" "$GREEN"
else
    print_msg "✗ Python3: FALTA" "$RED"
fi

if command -v nmap &> /dev/null; then
    print_msg "✓ Nmap: INSTALADO" "$GREEN"
else
    print_msg "✗ Nmap: FALTA" "$YELLOW"
fi

if command -v git &> /dev/null; then
    print_msg "✓ Git: INSTALADO" "$GREEN"
fi

if [ -f "python.py" ]; then
    print_msg "✓ python.py: LISTO" "$GREEN"
fi

if [ -d "scan_results" ]; then
    print_msg "✓ Directorios: CREADOS" "$GREEN"
fi

echo ""
print_msg "══════════════════════════════════════" "$CYAN"
print_msg "   INSTALACIÓN COMPLETADA" "$GREEN"
print_msg "══════════════════════════════════════" "$CYAN"
echo ""

print_msg "EJECUTAR:" "$BLUE"
print_msg "  ./python.py" "$GREEN"
echo ""

if [ "$IS_TERMUX" = true ]; then
    print_msg "NOTAS TERMUX:" "$YELLOW"
    print_msg "• Algunos scans requieren permisos especiales" "$YELLOW"
    print_msg "• Usa: termux-setup-storage si necesitas" "$YELLOW"
    echo ""
fi

print_msg "Presiona Enter para salir..." "$GREEN"
read -r

clear
echo -e "${GREEN}¡Listo! Ejecuta: ./python.py${NC}"
exit 0
