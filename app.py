import argparse
import socket
import ssl
import sys # Import sys for exit

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

user_agent = "CCBot/2.0"

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

try:
    # Removed hrequests imports
    from curl_cffi import requests as curl_requests # Use requests submodule for convenience
except ImportError:
    print("Please install requirements first: pip install -r requirements.txt")
    sys.exit(1) # Use sys.exit

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

# Removed create_browser_session function

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

def main():
    # Removed session variable
    banner_received = False
    http_response_received = False
    expects_tls = False
    initial_connection_succeeded = False # Track if initial connection works

    try:
        parser = argparse.ArgumentParser(description="Check TCP port, attempt banner grab/HTTP GET, check TLS, and perform curl_cffi request.")
        parser.add_argument('--ip_address', required=True, help='Target IP Address')
        parser.add_argument('--tcp_port', required=True, type=int, help='Target TCP Port') # Directly use type=int
        args = parser.parse_args()

        ip_address = args.ip_address
        tcp_port = args.tcp_port # Already an int

        # --- Step A: Initial TCP Connection ---
        print(f"# A. Attempting initial connection to {ip_address}:{tcp_port}...")
        sock = None
        try:
            sock = socket.create_connection((ip_address, tcp_port), timeout=5)
            print(f"[+] Initial connection to {ip_address}:{tcp_port} successful.")
            initial_connection_succeeded = True

            # --- Step B: Banner Grabbing ---
            print(f"# B. Attempting to receive banner from {ip_address}:{tcp_port}...")
            sock.settimeout(3) # Short timeout for banner grab
            try:
                banner = sock.recv(1024)
                if banner:
                    print(f"[+] Received Banner ({len(banner)} bytes):")
                    try:
                        print(banner.decode('utf-8', errors='replace')) # Try decoding as UTF-8
                    except Exception as decode_err:
                         print(f"[!] Error decoding banner: {decode_err}")
                         print(f"Raw Banner (repr): {repr(banner)}")
                    banner_received = True
                else:
                    print("[-] Connection closed by remote host before banner received.")
                    banner_received = False # Explicitly false
            except socket.timeout:
                print("[-] Timed out waiting for banner.")
                banner_received = False
            except socket.error as e:
                print(f"[!] Socket error during banner receive: {e}")
                banner_received = False
            except Exception as e:
                print(f"[!] Unexpected error during banner receive: {e}")
                banner_received = False

            # --- Step C: Manual HTTP GET (if no banner) ---
            if not banner_received:
                print(f"# C. No banner received, attempting manual HTTP GET to {ip_address}:{tcp_port}...")
                try:
                    http_get = f"""GET / HTTP/1.1\r
Host: {ip_address}\r
User-Agent: {user_agent}\r
Accept: */*\r
Connection: close\r
\r
""".encode('utf-8')
                    print("[*] Sending HTTP GET request...")
                    # print(f"--- Request ---
# {http_get.decode('utf-8')}--- End Request ---") # Optional: print request
                    sock.sendall(http_get)

                    # Receive response
                    print("[*] Waiting for HTTP response...")
                    response = b""
                    sock.settimeout(10) # Timeout for response
                    while True:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                print("[-] Connection closed by remote host.")
                                break
                            response += chunk
                        except socket.timeout:
                            print("[-] Timed out waiting for more data.")
                            break
                        except socket.error as e:
                            print(f"[!] Socket error during HTTP response receive: {e}")
                            break

                    if response:
                        print(f"[+] Received HTTP Response ({len(response)} bytes):")
                        try:
                            decoded_response = response.decode('utf-8', errors='replace')
                            if len(decoded_response) > 10000:
                                print(f"## Received Response (truncated to 10000 chars):\n{decoded_response[:10000]}...")
                            else:
                                print(f"## Received Response:\n{decoded_response}")
                        except Exception as decode_err:
                            print(f"[!] Error decoding response: {decode_err}")
                            print(f"Raw Response (repr): {repr(response)}")
                        http_response_received = True
                    else:
                        print("[-] No response received after manual HTTP GET.")
                        http_response_received = False

                except socket.error as e:
                    print(f"[!] Socket error during manual HTTP GET send/recv: {e}")
                except Exception as e:
                    print(f"[!] Unexpected error during manual HTTP GET: {e}")

        except socket.timeout:
            print(f"[-] Initial connection to {ip_address}:{tcp_port} timed out.")
            initial_connection_succeeded = False
        except socket.error as e:
            print(f"[-] Could not connect to {ip_address}:{tcp_port} (Initial). Error: {e}")
            initial_connection_succeeded = False
        except Exception as e:
             print(f"[!] Unexpected error during initial connection or steps B/C: {e}")
             initial_connection_succeeded = False
        finally:
            if sock:
                print("[*] Closing initial socket.")
                try:
                    sock.close()
                except socket.error as e:
                    print(f"[!] Error closing initial socket: {e}")
                sock = None # Ensure sock is None after closing

        # --- Step D: TLS Check (if initial connection succeeded) ---
        if initial_connection_succeeded and not banner_received:
            print(f"# D. Performing TLS handshake check on {ip_address}:{tcp_port}...")
            sock_tls = None
            try:
                # Establish a *new* connection for the TLS check
                sock_tls = socket.create_connection((ip_address, tcp_port), timeout=5)
                print("[*] Established temporary connection for TLS check.")
                context = ssl.create_default_context()
                # Loosen checks for self-signed certs / IP address usage
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                print("[*] Attempting TLS handshake...")
                # Use server_hostname=ip_address for SNI, though check_hostname=False ignores mismatch later
                with context.wrap_socket(sock_tls, server_hostname=ip_address) as sslsock:
                    sslsock.settimeout(5) # Handshake timeout
                    # Handshake happens implicitly here with context manager in newer Python versions
                    # For older versions, you might need sslsock.do_handshake() explicitly before this line
                    # cert = sslsock.getpeercert() # Optional: Get cert info
                    # print(f"[+] TLS Handshake Successful. Cipher: {sslsock.cipher()}") # Optional: Print cipher
                    # if cert:
                    #    print(f"[+] Peer Certificate: {cert}")
                    print("[+] TLS handshake successful. Service likely expects TLS (e.g., HTTPS).")
                    expects_tls = True

            except ssl.SSLError as e:
                print(f"[-] TLS handshake failed: {e}. Service likely expects a plain protocol (e.g., HTTP).")
                expects_tls = False
            except socket.timeout:
                print(f"[-] Timed out during TLS check connection or handshake.")
                expects_tls = False # Assume no TLS if timeout occurs here
            except socket.error as e:
                print(f"[-] Socket error during TLS check connection: {e}")
                expects_tls = False # Assume no TLS if connection fails
            except Exception as e:
                print(f"[!] Unexpected error during TLS check: {e}")
                expects_tls = False
            finally:
                if sock_tls and not expects_tls: # wrap_socket closes the underlying socket on success when used as context manager
                     print("[*] Closing temporary socket for TLS check (handshake failed or context manager exited).")
                     try:
                        sock_tls.close()
                     except socket.error as e:
                        print(f"[!] Error closing temporary TLS socket: {e}")
        elif initial_connection_succeeded and banner_received:
             print("[*] Skipping TLS check because a banner was received in Step B.")


        # --- Step E/F: curl_cffi Request (if initial connection succeeded) ---
        if initial_connection_succeeded and not banner_received:
            target_url = ""
            protocol = ""

            if expects_tls:
                # --- Step E: HTTPS Request ---
                protocol = "https"
                if tcp_port == 443:
                    target_url = f"https://{ip_address}/"
                else:
                    target_url = f"https://{ip_address}:{tcp_port}/"
                print(f"# E. Service expects TLS. Attempting HTTPS GET request to {target_url} using curl_cffi...")

            else:
                # --- Step F: HTTP Request ---
                protocol = "http"
                if tcp_port == 80:
                    target_url = f"http://{ip_address}/"
                else:
                    target_url = f"http://{ip_address}:{tcp_port}/"
                print(f"# F. Service does not expect TLS (or check failed). Attempting HTTP GET request to {target_url} using curl_cffi...")

            try:
                # Use verify=False for HTTPS to ignore certificate verification errors
                # (common when accessing via IP or using self-signed certs)
                print(f"[*] Making {protocol.upper()} request with impersonation (chrome)...")
                response = curl_requests.get(
                    target_url,
                    impersonate="chrome110", # Use a specific recent version
                    # proxies=proxies, # Example: Add proxies if needed
                    timeout=15, # Request timeout
                    verify=False # Disable SSL verification
                    #verify=False if protocol == "https" else True # Only set verify=False for HTTPS
                )
                print(f"[+] curl_cffi {protocol.upper()} request successful.")
                print("--- curl_cffi Response Details ---")
                print(f"Status Code: {response.status_code} ({response.reason})")
                print(f"OK: {response.ok}")
                print(f"URL (final): {response.url}")
                print(f"Encoding: {response.encoding}")
                print(f"Elapsed Time: {response.elapsed}")
                print("Headers:")
                for key, value in response.headers.items():
                    print(f"  {key}: {value}")
                # print("Cookies:") # curl_cffi response object might not expose cookies directly like requests
                # if response.cookies:
                #     for cookie in response.cookies:
                #         print(f"  {cookie.name}={cookie.value}")
                # else:
                #      print("  (No cookies received or not accessible)")
                print("History (Redirects):")
                if response.history:
                    for i, resp_hist in enumerate(response.history):
                        print(f"  {i+1}: {resp_hist.status_code} -> {resp_hist.url}")
                else:
                    print("  (No redirects)")
                print(f"## Content (first 10000 bytes of {len(response.content)} total):")
                # Use response.text which handles decoding based on headers/chardet
                print(response.text[:10000])
                # Or force decode if needed: print(response.content[:500].decode(response.encoding or 'utf-8', errors='ignore'))
                print("---------------------------------")

            except curl_requests.errors.CurlError as e:
                print(f"[!] curl_cffi request failed: {e}")
            except Exception as e:
                print(f"[!] Unexpected error during curl_cffi request: {e}")
        elif initial_connection_succeeded and banner_received:
             print("[*] Skipping curl_cffi request because a banner was received in Step B.")
        else: # This handles the case where initial_connection_succeeded is False
            print("[*] Skipping TLS check and curl_cffi request because initial connection failed.")


        print("### --- Check Complete --- ###")
        return 0 # Indicate success if script ran through

    except socket.gaierror as e:
        print(f"[!] Error resolving IP address '{args.ip_address}': {e}")
        return 1
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc() # Print detailed traceback for debugging
        return 1
    # Removed finally block that closed hrequests session

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

if __name__ == "__main__":
    sys.exit(main()) # Use sys.exit for cleaner exit code handling