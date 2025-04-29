# runner_wiseportcheck

Q. will you explain the logic flow of the @app.py now, as it relates to what it does first, second, third, etc. when checking remote servers?

A. Okay, let's break down the logic flow of `app.py` step-by-step:

1.  **Initialization and Argument Parsing:**
    *   The script imports necessary libraries (`argparse`, `socket`, `ssl`, `sys`, `curl_cffi.requests`).
    *   It defines the `main` function.
    *   Inside `main`, it parses command-line arguments using `argparse` to get the target `--ip_address` and `--tcp_port`.

2.  **Step A: Initial TCP Connection Attempt:**
    *   It attempts to establish a basic TCP connection to the specified IP and port using `socket.create_connection` with a 5-second timeout.
    *   A flag `initial_connection_succeeded` tracks the outcome.
    *   **If connection fails (timeout or error):** It prints an error message, sets the flag to `False`, ensures the socket (if partially opened) is closed, and skips ahead to the *end* of the checks (Step E/F are skipped).
    *   **If connection succeeds:** It prints a success message, sets the flag to `True`, and proceeds to the next step.

3.  **Step B: Banner Grabbing (Only if Step A succeeded):**
    *   It attempts to receive initial data (a "banner") from the server using the established socket (`sock.recv(1024)`) with a short 3-second timeout.
    *   A flag `banner_received` tracks the outcome.
    *   **If banner received:** It prints the decoded banner (UTF-8 with replacements for errors) and sets `banner_received = True`.
    *   **If no banner (timeout, socket error, connection closed prematurely):** It prints a relevant message and sets `banner_received = False`.

4.  **Step C: Manual HTTP GET (Only if Step A succeeded AND Step B failed):**
    *   If no banner was received in Step B, the script assumes the service might be HTTP-based and requires a client request first.
    *   It constructs a basic `GET / HTTP/1.1` request string, including `Host`, `Connection: close`, and `User-Agent` headers.
    *   It sends this request using `sock.sendall()`.
    *   It then attempts to receive the response in chunks (`sock.recv(4096)`) with a 10-second timeout until the connection is closed or times out.
    *   A flag `http_response_received` tracks the outcome.
    *   **If response received:** It prints the decoded response (UTF-8 with replacements) and sets `http_response_received = True`. If the response is larger than 10000 characters, it will be truncated in the display.
    *   **If no response or error during send/receive:** It prints a relevant message and sets `http_response_received = False`.

5.  **Cleanup After Initial Connection Steps (A, B, C):**
    *   A `finally` block associated with the initial connection attempt ensures that the socket (`sock`) used for steps A, B, and C is always closed cleanly, regardless of success or failure within those steps.

6.  **Step D: TLS Handshake Check (Only if Step A succeeded AND no banner was received):**
    *   This step only runs if the initial connection (Step A) worked AND no banner was received in Step B.
    *   It establishes a ***new***, separate TCP connection to the target IP and port (timeout 5s) specifically for the TLS check.
    *   It creates a default SSL context (`ssl.create_default_context()`).
    *   It disables strict certificate validation (`context.check_hostname = False` and `context.verify_mode = ssl.CERT_NONE`) to allow connections to servers using IP addresses or self-signed certificates without immediate failure.
    *   It attempts to wrap the new socket with TLS using `context.wrap_socket()`, providing the `ip_address` as `server_hostname` (for SNI). This is done within a `with` statement, which handles the TLS handshake implicitly and socket closure on success. A 5-second timeout is set on the wrapped socket for the handshake.
    *   A flag `expects_tls` tracks the outcome.
    *   **If handshake succeeds:** It prints a success message and sets `expects_tls = True`. The `with` statement automatically closes the TLS socket.
    *   **If handshake fails (`ssl.SSLError`, `socket.timeout`, `socket.error`, etc.):** It prints the specific error, sets `expects_tls = False`, and a `finally` block ensures the underlying temporary socket (`sock_tls`) is closed (since the `with` statement might not have completed successfully).
    *   **If a banner was received in Step B:** It skips the TLS check entirely with a message indicating the reason.

7.  **Step E/F: `curl_cffi` Request (Only if Step A succeeded AND no banner was received):**
    *   This step uses the `curl_cffi` library (impersonating Chrome 110) to make a final HTTP or HTTPS request based on the result of the TLS check (Step D).
    *   This step is skipped if a banner was received in Step B, with a message indicating the reason.
    *   **Scenario E (if `expects_tls` is True):**
        *   Sets `protocol = "https"` and constructs the `target_url` (e.g., `https://{ip_address}:{tcp_port}/` or `https://{ip_address}/` if port is 443).
        *   Prints a message indicating an HTTPS attempt.
        *   Makes a GET request using `curl_requests.get(target_url, impersonate="chrome110", timeout=15, verify=False)`. **Note:** `verify=False` explicitly disables SSL certificate verification for this request.
    *   **Scenario F (if `expects_tls` is False):**
        *   Sets `protocol = "http"` and constructs the `target_url` (e.g., `http://{ip_address}:{tcp_port}/` or `http://{ip_address}/` if port is 80).
        *   Prints a message indicating an HTTP attempt.
        *   Makes a GET request using `curl_requests.get(target_url, impersonate="chrome110", timeout=15, verify=False)`. (`verify=False` has no effect on HTTP but is set unconditionally in the code).
    *   **Request Outcome (Either Scenario):**
        *   **If `curl_requests.get` succeeds:** It prints detailed response information: status code, reason phrase, final URL (after redirects), OK status, encoding, elapsed time, headers, redirect history, and the first 10000 bytes of the response body (`response.text`).
        *   **If `curl_requests.get` fails (e.g., `curl_requests.errors.CurlError`, network issues):** It prints an error message indicating the failure.
    *   **If initial connection failed:** A message indicates that both TLS check and curl_cffi request are being skipped because the initial connection failed.

8.  **Final Output and Exit:**
    *   The script prints "### --- Check Complete --- ###".
    *   The `main` function returns `0` if the script generally completed its flow, or `1` if specific errors like DNS resolution failure (`socket.gaierror`) or other unexpected exceptions occurred.
    *   The script exits using `sys.exit()` with the return code from `main()`. A top-level `try...except ImportError` handles cases where `curl_cffi` isn't installed.
