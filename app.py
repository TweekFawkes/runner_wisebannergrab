import argparse

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

try:
    import socket
except ImportError:
    print("Please install requirements.txt first: pip install -r requirements.txt")
    exit(1)

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--ip_address', required=True, help='IP Address to Get Whois Information For')
        parser.add_argument('--tcp_port', required=True, help='TCP Port to Check')
        args = parser.parse_args()

        ip_address = args.ip_address
        tcp_port = int(args.tcp_port) # Convert port to integer

        ### --- Port Check Logic Start --- ###
        print(f"\n# Attempting to connect to {ip_address}:{tcp_port}...")
        sock = None
        try:
            sock = socket.create_connection((ip_address, tcp_port), timeout=5)
            print(f"[+] Port {tcp_port} appears to be open.")
            
            # Try receiving banner
            sock.settimeout(3) # Short timeout for banner grab
            try:
                banner = sock.recv(1024)
                if banner:
                    print(f"## Received Banner:\n{banner.decode(errors='ignore')}")
                else:
                    print("[-] No banner received immediately. Assuming HTTP or similar service.")
                    # Send HTTP GET request
                    http_get = f"GET / HTTP/1.1\r\nHost: {ip_address}\r\nConnection: close\r\n\r\n".encode()
                    print(f"[*] Sending HTTP GET request...")
                    sock.sendall(http_get)
                    
                    # Receive response
                    response = b""
                    while True:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                        except socket.timeout:
                            break # Stop receiving if timeout occurs
                    if response:
                        print(f"## Received Response:\n{response.decode(errors='ignore')}")
                    else:
                        print("[-] No response received after GET request.")
            except socket.timeout:
                print("[-] Timed out waiting for banner/response. Service might not send data proactively.")
            except Exception as e:
                print(f"[!] Error during banner grab/HTTP request: {e}")
        
        except socket.timeout:
            print(f"[-] Connection to {ip_address}:{tcp_port} timed out.")
        except socket.error as e:
            print(f"[-] Could not connect to {ip_address}:{tcp_port}. Error: {e}")
        finally:
            if sock:
                sock.close()
        print("### --- Port Check Logic End --- ###\n")
        ###
        return 0
    except socket.gaierror as e:
        print(f"[!] Error resolving IP address or connecting: {e}")
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return 1

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

if __name__ == "__main__":
    exit(main())