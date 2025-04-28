import argparse

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

try:
    import socket
    import ssl
    import hrequests
    from hrequests import BrowserSession # Import BrowserSession
except ImportError:
    print("Please install requirements.txt first: pip install -r requirements.txt")
    exit(1)

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

def create_browser_session(session):
    if session is None:
        # Create a BrowserSession instance
        print("[*] Initializing hrequests BrowserSession (camoufox)...")
        session = BrowserSession(browser='firefox', mock_human=True, os='lin')
        print("[*] BrowserSession initialized.")
    return session

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

def main():
    session = None # Initialize session to None
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
            # Initial TCP connection
            sock = socket.create_connection((ip_address, tcp_port), timeout=5)
            print(f"[+] Port {tcp_port} appears to be open. Checking for TLS...")

            # --- TLS Handshake Check --- #
            expects_tls = False
            tls_check_failed = False # Flag to indicate if we need to reconnect for plain HTTP
            try_https_despite_sni_error = False # Flag for specific SNI error case
            original_sock = sock # Keep a reference to the original socket
            sslsock = None
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sslsock = context.wrap_socket(original_sock, server_hostname=ip_address, do_handshake_on_connect=False)
                sslsock.settimeout(3)
                sslsock.do_handshake()
                print("[+] TLS handshake successful. Service likely expects TLS (e.g., HTTPS).")
                expects_tls = True
                try:
                    sslsock.close() # Close the SSL socket, underlying original_sock is also closed
                except: pass

            except ssl.SSLError as e:
                # Check for the specific SNI error
                if "TLSV1_UNRECOGNIZED_NAME" in str(e) or "tlsv1 unrecognized name" in str(e):
                    print(f"[-] TLS handshake failed with SNI error: {e}. Server expects TLS but may dislike IP address.")
                    try_https_despite_sni_error = True
                else:
                    # Handshake failed for other reasons, likely not a TLS service
                    print(f"[-] TLS handshake failed: {e}. Service likely expects a plain protocol (e.g., HTTP).")
                    tls_check_failed = True # Mark for plain HTTP fallback
            except socket.timeout:
                print("[-] Timed out during TLS handshake attempt.")
                tls_check_failed = True # Mark for plain HTTP fallback
            except Exception as e:
                print(f"[!] Error during TLS check: {e}")
                tls_check_failed = True # Mark for plain HTTP fallback
            # --- End TLS Handshake Check --- #

            # Case 1: SNI error occurred, but we still want to try HTTPS GET
            if try_https_despite_sni_error:
                print("[*] Closing socket after SNI error, attempting HTTPS GET with hrequests...")
                try:
                    original_sock.close() # Close the potentially corrupted original socket
                except: pass
                try:
                    # Use the session for the HTTPS GET request
                    session = create_browser_session(session)
                    # Add verify=False to ignore SSL certificate errors
                    response = session.get(f'https://{ip_address}:{tcp_port}', verify=False)
                    print("--- hrequests HTTPS Response Details (after SNI error) ---")
                    # (Identical printing logic as the successful handshake case)
                    print(f"Status Code: {response.status_code} ({response.reason})")
                    print(f"OK: {response.ok}")
                    print(f"URL: {response.url}")
                    print(f"Encoding: {response.encoding}")
                    print(f"Elapsed Time: {response.elapsed}")
                    print("Headers:")
                    for key, value in response.headers.items():
                        print(f"  {key}: {value}")
                    print("Cookies:")
                    if response.cookies:
                        for cookie in response.cookies:
                            print(f"  {cookie.name}={cookie.value}")
                    else:
                        print("  (No cookies received)")
                    print("History (Redirects):")
                    if response.history:
                        for resp_hist in response.history:
                            print(f"  {resp_hist.status_code} -> {resp_hist.url}")
                    else:
                        print("  (No redirects)")
                    print("Content (first 500 bytes):")
                    print(response.content[:500].decode(errors='ignore'))
                    print("---------------------------------------------------------")
                except Exception as e: # Catch general exception for hrequests call
                    error_message = str(e)
                    print(f"[!] hrequests HTTPS GET request failed (after SNI error): {error_message}")
                    # Check if the specific TLS unrecognized name error occurred during the hrequests HTTPS attempt
                    if "remote error: tls: unrecognized name" in error_message or "tlsv1 unrecognized name" in error_message:
                        print("[*] HTTPS GET failed with TLS unrecognized name, falling back to HTTP GET...")
                        try:
                            # Use the session for the HTTP GET request
                            session = create_browser_session(session)
                            # No verify=False needed for HTTP
                            response = session.get(f'http://{ip_address}:{tcp_port}')
                            print("--- hrequests HTTP Response Details (Fallback after SNI->HTTPS fail) ---")
                            print(f"Status Code: {response.status_code} ({response.reason})")
                            print(f"OK: {response.ok}")
                            print(f"URL: {response.url}")
                            print(f"Encoding: {response.encoding}")
                            print(f"Elapsed Time: {response.elapsed}")
                            print("Headers:")
                            for key, value in response.headers.items():
                                print(f"  {key}: {value}")
                            print("Cookies:")
                            if response.cookies:
                                for cookie in response.cookies:
                                    print(f"  {cookie.name}={cookie.value}")
                            else:
                                print("  (No cookies received)")
                            print("History (Redirects):")
                            if response.history:
                                for resp_hist in response.history:
                                    print(f"  {resp_hist.status_code} -> {resp_hist.url}")
                            else:
                                print("  (No redirects)")
                            print("Content (first 500 bytes):")
                            print(response.content[:500].decode(errors='ignore'))
                            print("----------------------------------------------------------------------")
                        except Exception as fallback_e:
                            print(f"[!] HTTP GET fallback failed: {fallback_e}")
                    # else: The HTTPS GET failed for a different reason, no further fallback.

            # Case 2: TLS handshake failed for other reasons, reconnect and try plain HTTP
            elif tls_check_failed:
                print("[*] Closing potentially corrupted socket after failed TLS attempt...")
                try:
                    # Close the original socket explicitly, as TLS attempt might have corrupted it
                    original_sock.close()
                except: pass # Ignore errors if already closed

                print("[*] Reconnecting with a plain socket...")
                sock = None # Reset sock before trying to reconnect
                try:
                    # Create a *new* plain connection
                    sock = socket.create_connection((ip_address, tcp_port), timeout=5)
                    print("[+] Reconnected successfully.")

                    # Now proceed with non-TLS banner grab / request using the *new* sock
                    print("[*] Proceeding with non-TLS banner grab / request...")
                    sock.settimeout(3)
                    try:
                        banner = sock.recv(1024)
                        if banner:
                            print(f"## Received Banner:\n{banner.decode(errors='ignore')}")
                        else:
                            print("[-] No banner received immediately. Assuming HTTP or similar service requiring client initiation.")
                            # Try HTTP GET request with the session since no banner was received
                            try:
                                session = create_browser_session(session)
                                print(f"[*] Attempting HTTP GET request with hrequests session to http://{ip_address}:{tcp_port}")
                                # Use the session for the GET request
                                response = session.get(f'http://{ip_address}:{tcp_port}')

                                print("--- hrequests Response Details ---")
                                print(f"Status Code: {response.status_code} ({response.reason})")
                                print(f"OK: {response.ok}")
                                print(f"URL: {response.url}")
                                print(f"Encoding: {response.encoding}")
                                print(f"Elapsed Time: {response.elapsed}")
                                print("Headers:")
                                for key, value in response.headers.items():
                                    print(f"  {key}: {value}")
                                print("Cookies:")
                                if response.cookies:
                                    for cookie in response.cookies:
                                        print(f"  {cookie.name}={cookie.value}")
                                else:
                                    print("  (No cookies received)")
                                print("History (Redirects):")
                                if response.history:
                                    for resp_hist in response.history:
                                        print(f"  {resp_hist.status_code} -> {resp_hist.url}")
                                else:
                                    print("  (No redirects)")
                                print("Content (first 500 bytes):")
                                print(response.content[:500].decode(errors='ignore'))
                                print("---------------------------------")

                            except Exception as e: # Catch general exception for hrequests call
                                print(f"[!] hrequests GET request failed: {e}")

                    except socket.timeout:
                        print("[-] Timed out waiting for banner. Assuming HTTP or similar service requiring client request.")
                        # Also try HTTP GET request with the session here if banner times out
                        try:
                            session = create_browser_session(session)
                            print(f"[*] Attempting HTTP GET request with hrequests session to http://{ip_address}:{tcp_port} after banner timeout")
                            response = session.get(f'http://{ip_address}:{tcp_port}')

                            print("--- hrequests Response Details ---")
                            print(f"Status Code: {response.status_code} ({response.reason})")
                            print(f"OK: {response.ok}")
                            print(f"URL: {response.url}")
                            print(f"Encoding: {response.encoding}")
                            print(f"Elapsed Time: {response.elapsed}")
                            print("Headers:")
                            for key, value in response.headers.items():
                                print(f"  {key}: {value}")
                            print("Cookies:")
                            if response.cookies:
                                for cookie in response.cookies:
                                    print(f"  {cookie.name}={cookie.value}")
                            else:
                                print("  (No cookies received)")
                            print("History (Redirects):")
                            if response.history:
                                for resp_hist in response.history:
                                    print(f"  {resp_hist.status_code} -> {resp_hist.url}")
                            else:
                                print("  (No redirects)")
                            print("Content (first 500 bytes):")
                            print(response.content[:500].decode(errors='ignore'))
                            print("---------------------------------")
                        except Exception as e: # Catch general exception for hrequests call
                            print(f"[!] hrequests GET request failed after banner timeout: {e}")

                    except Exception as e:
                        # Catch other socket errors during banner grab
                        print(f"[!] Error during banner grab attempt: {e}")

                except socket.timeout:
                    print(f"[-] Reconnection attempt to {ip_address}:{tcp_port} timed out.")
                except socket.error as e:
                    print(f"[-] Could not reconnect to {ip_address}:{tcp_port}. Error: {e}")
                # The finally block below will handle closing this new sock if it exists

            # Case 3: TLS handshake succeeded initially
            elif expects_tls:
                # Original socket is closed by sslsock.close() after successful handshake
                print("[*] TLS expected. Attempting HTTPS GET request with hrequests session...")
                try:
                    session = create_browser_session(session)
                    # Use the session for the HTTPS GET request
                    # Add verify=False to ignore SSL certificate errors
                    response = session.get(f'https://{ip_address}:{tcp_port}', verify=False)

                    print("--- hrequests HTTPS Response Details ---")
                    print(f"Status Code: {response.status_code} ({response.reason})")
                    print(f"OK: {response.ok}")
                    print(f"URL: {response.url}")
                    print(f"Encoding: {response.encoding}")
                    print(f"Elapsed Time: {response.elapsed}")
                    print("Headers:")
                    for key, value in response.headers.items():
                        print(f"  {key}: {value}")
                    print("Cookies:")
                    if response.cookies:
                        for cookie in response.cookies:
                            print(f"  {cookie.name}={cookie.value}")
                    else:
                        print("  (No cookies received)")
                    print("History (Redirects):")
                    if response.history:
                        for resp_hist in response.history:
                            print(f"  {resp_hist.status_code} -> {resp_hist.url}")
                    else:
                        print("  (No redirects)")
                    print("Content (first 500 bytes):")
                    print(response.content[:500].decode(errors='ignore'))
                    print("---------------------------------")

                except Exception as e: # Catch general exception for hrequests call
                    print(f"[!] hrequests HTTPS GET request failed: {e}")

            # Else: Initial connection might have failed even before TLS check, handled by outer exception blocks.

        except socket.timeout:
            print(f"[-] Connection to {ip_address}:{tcp_port} timed out (initial connection)." )
        except socket.error as e:
            # This catches connection errors for the *initial* connection attempt
            print(f"[-] Could not connect to {ip_address}:{tcp_port} (initial attempt). Error: {e}")
        finally:
            # Ensure the *final* socket (original, reconnected, or none if HTTPS tried after SNI) is closed if it exists
            if 'sock' in locals() and sock and not try_https_despite_sni_error and not expects_tls:
                # Only close 'sock' if it's the reconnected one for plain HTTP
                try:
                    #print("[Debug] Closing reconnected plain socket in outer finally.")
                    sock.close()
                except: pass
            elif 'original_sock' in locals() and original_sock and (expects_tls or try_https_despite_sni_error):
                 # If TLS succeeded, original_sock was closed by sslsock.close().
                 # If TLS failed with SNI error, original_sock was closed before hrequests HTTPS attempt.
                 # No action needed here.
                 pass
            # Add a check in case initial connection failed before sock was assigned
            elif 'sock' not in locals() and 'original_sock' in locals() and original_sock:
                 try:
                      #print("[Debug] Closing original_sock because main logic wasn't reached")
                      original_sock.close()
                 except: pass

        print("### --- Port Check Logic End --- ###\n")
        ###
        return 0
    except socket.gaierror as e:
        print(f"[!] Error resolving IP address or connecting: {e}")
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return 1
    finally:
        # Ensure the browser session is closed if it was created
        if session:
            print("[*] Closing hrequests BrowserSession...")
            try:
                session.close()
                print("[*] BrowserSession closed.")
            except Exception as e:
                print(f"[!] Error closing BrowserSession: {e}")

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

if __name__ == "__main__":
    exit(main())