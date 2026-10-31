[English](README.md) [Portuguese](README_pt.md)
# iroh-ssh

[![Crates.io](https://img.shields.io/crates/v/iroh-ssh.svg)](https://crates.io/crates/iroh-ssh)
[![Documentation](https://docs.rs/iroh-ssh/badge.svg)](https://docs.rs/iroh-ssh)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![AUR](https://img.shields.io/aur/version/iroh-ssh-git)](https://aur.archlinux.org/packages/iroh-ssh-git)
[![Discord](https://img.shields.io/discord/1403836127458099381?logo=discord&label=Discord)](https://discord.gg/c22SPMYAwZ)

**Usa SSH a cualquier maquina sin usar IP, tras una NAT/firewall y sin requerir redireccionamiento de puertos o configurar una VPN.**

```bash
# En el servidor
> iroh-ssh server --persist

    Connect to this this machine:

    ssh -o ProxyCommand="iroh-ssh proxy %h" my-user@bb8e1a5661a6dfa9ae2dd978922f30f524f6fd8c99b3de021c53f292aae74330


# En el cliente
> ssh -o ProxyCommand="iroh-ssh proxy %h" user@bb8e1a5661a6dfa9ae2dd978922f30f524f6fd8c99b3de021c53f292aae74330
# o con certificados ssh
> ssh -o ProxyCommand="iroh-ssh proxy %h" -i ~/.ssh/id_rsa_my_cert my-user@bb8e1a5661a6dfa9ae2dd978922f30f524f6fd8c99b3de021c53f292aae74330
```

**Y eso es todo lo que se necesita.** (requiere tener ssh/(un servidor ssh) instalado)

---

## Instalación

```bash
cargo install iroh-ssh
```

Arch Linux ([AUR](https://aur.archlinux.org/packages/iroh-ssh-git))
```bash
yay -S iroh-ssh-git
```

Descarga y configura automáticamente el binario para tu sistema operativo desde [GitHub Releases](https://github.com/rustonbsd/iroh-ssh/releases):

Linux
```bash
# Linux
wget https://github.com/rustonbsd/iroh-ssh/releases/download/0.2.12/iroh-ssh.linux
chmod +x iroh-ssh.linux
sudo mv iroh-ssh.linux /usr/local/bin/iroh-ssh
```

Linux (ARM)
```bash
# Linux
wget https://github.com/rustonbsd/iroh-ssh/releases/download/0.2.12/iroh-ssh.linux-aarch64
chmod +x iroh-ssh.linux-aarch64
sudo mv iroh-ssh.linux-aarch64 /usr/local/bin/iroh-ssh
```

macOS (ARM)
```bash
# macOS arm
curl -LJO https://github.com/rustonbsd/iroh-ssh/releases/download/0.2.12/iroh-ssh.macos
chmod +x iroh-ssh.macos
sudo mv iroh-ssh.macos /usr/local/bin/iroh-ssh
```

Windows
```bash
# Windows x86 64bit
curl -L -o iroh-ssh.exe https://github.com/rustonbsd/iroh-ssh/releases/download/0.2.12/iroh-ssh.exe
mkdir %LOCALAPPDATA%\iroh-ssh
move iroh-ssh.exe %LOCALAPPDATA%\iroh-ssh\
setx PATH "%PATH%;%LOCALAPPDATA%\iroh-ssh"
```

Verifica que la instalación fue exitosa
```bash
# reiniciar primero su terminal
> iroh-ssh --help
```

---

## Conexion del cliente

```bash
# Instalar para su distribución primero (ver arriba)
# Conectar desde cualquier lugar
> ssh -o ProxyCommand="iroh-ssh proxy %h" my-user@38b7dc10df96005255c3beaeaeef6cfebd88344aa8c85e1dbfc1ad5e50f372ac

# o en ~/.ssh/config, y luego `ssh my-server`
Host my-server
    HostName 38b7dc10df96005255c3beaeaeef6cfebd88344aa8c85e1dbfc1ad5e50f372ac
    User my-user
    ProxyCommand iroh-ssh proxy %h
```

Funciona a través de cualquier firewall, NAT o red privada. Sin configuración necesaria.

---

## Configurando el servidor

```bash
# Instalar para su distribución primero (ver arriba)
# (usar con tmux)

> iroh-ssh server --persist

    Connect to this this machine:

    ssh -o ProxyCommand="iroh-ssh proxy %h" my-user@bb8e1a5661a6dfa9ae2dd978922f30f524f6fd8c99b3de021c53f292aae74330

    (using persistent keys in /home/my-user/.ssh/irohssh_ed25519)

    Server listening for iroh connections...
    client -> iroh-ssh -> direct connect -> iroh-ssh -> local ssh :22
    Waiting for incoming connections...
    Press Ctrl+C to exit

```

o para llaves efimeras

```bash
# Instalar para su distribución primero (ver arriba)
# (usar con tmux)

> iroh-ssh server

    Connect to this this machine:

    ssh -o ProxyCommand="iroh-ssh proxy %h" my-user@bb8e1a5661a6dfa9ae2dd978922f30f524f6fd8c99b3de021c53f292aae74330

    warning: (using ephemeral keys, run 'iroh-ssh server --persist' to create persistent keys)

    client -> iroh-ssh -> direct connect -> iroh-ssh -> local ssh :22
    Waiting for incoming connections...
    Press Ctrl+C to exit
    Server listening for iroh connections...

```

Mostrar su ID de nodo y compártalo para permitir la conexión

---

## Como funciona

```
┌─────────────┐          ┌─────────────────┐          ┌─────────────┐
│     SSH     │─────────▶│  Tunel QUIC     │─────────▶│  iroh-ssh   │
│   Cliente   │          │  (Red P2P)      │          │  servidor   │
└─────────────┘          └─────────────────┘          └─────────────┘
      │                           ▲                            │
      │                           │                            │
      ▼                           │                            ▼
┌─────────────┐          ┌─────────────┐          ┌──────────────────┐
│ ProxyCommand│          │  iroh-ssh   │          │ Servidor SSH     │
│ iroh-ssh    │──────────│    proxy    │          │ localhost:22     │
│ proxy %h    │          │             │          └──────────────────┘
└─────────────┘          └─────────────┘
```

1. **Cliente SSH**: Invoca `iroh-ssh proxy` a través del ProxyCommand de SSH
2. **Proxy**: Establece una conexión QUIC a través de la red P2P de Iroh (traspaso NAT automatico)
3. **Servidor**: Acepta la conexión y proxifica al daemon SSH local (puerto 22)
4. **Autenticación**: Seguridad estándar SSH end-to-end sobre túnel QUIC cifrado

## Escenarios de uso

- **VNC/RDP sobre SSH**: Acceder de forma segura a escritorios gráficos de forma remota
- **Extensión SSH de VisualStudio**: Desarrollar en máquinas remotas sin problemas
- **Servidores remotos**: Acceder a instancias en la nube sin exponer puertos SSH
- **Redes domesticas**: Conectar a dispositivos tras un router/firewall
- **Redes corporativas**: Saltarse politicas de redes restrictivas
- **Dispositivos IoT**: SSH a dispositivos embebidos en redes privadas
- **Desarrollo**: Acceder a servidores de pruebas y máquinas de compilacion

## Comandos

```bash
# Modos de servidor
> iroh-ssh server --persist          # Modo interactivo, por ejemplo usar tmux (en el puerto 22 default SSH)
> iroh-ssh server --ssh-port 2222    # Usando un puerto SSH personalizado (con llaves efimeras)

# Conexión de cliente
> ssh -o ProxyCommand="iroh-ssh proxy %h" user@<ENDPOINT_ID>                 # Conectarse a un servidor remoto
> ssh -o ProxyCommand="iroh-ssh proxy --relay-url <URL> %h" user@<ENDPOINT_ID>   # Definir opciones de relay en el proxy
```

## Modelo de seguridad

- **Acceso por ID de Nodo**: Cualquier persona con el ID de Nodo puede acceder a su puerto SSH
- **Autenticación SSH**: Se admite la autenticación de llave y certificados SSH.
- **Llaves persistentes**: Utiliza un par de llave dedicado en `.ssh/iroh_ssh_ed25519`
- **Cifrado QUIC**: Cifrado en la capa de transporte entre puntos finales

## Avances

- [x] Autenticación con contraseña
- [x] Llaves SSH persistentes
- [x] Adicionar la opción -p para persistencia

## Licencia

Licenciado tanto la Licencia Apache 2.0 o la Licencia MIT a su elección.
