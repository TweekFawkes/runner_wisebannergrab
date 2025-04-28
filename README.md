# runner_wiseportcheck

Q. will you explain the logic flow of the @app.py now, as it relates to what it does first, second, third, etc. when checking remote servers?

A. Okay, let's break down the logic flow of `app.py` step-by-step:

1.  **Initialization and Argument Parsing:**
    *   The script imports necessary libraries (`socket`, `ssl`, `hrequests`, `argparse`).
    *   It defines the `main` function.
    *   Inside `main`, it parses command-line arguments to get the target `--ip_address` and `--tcp_port`.

2.  **Initial TCP Connection Attempt:**
    *   It tries to establish a basic TCP connection to the specified IP and port using `socket.create_connection` with a 5-second timeout.
    *   **If connection fails (timeout or error):** It prints an error message indicating the failure and jumps to the `finally` block for cleanup.
    *   **If connection succeeds:** It prints that the port appears open and proceeds to the next step.

3.  **TLS Handshake Check:**
    *   It takes the established socket (`original_sock`) and attempts to wrap it with SSL/TLS using `context.wrap_socket`.
    *   It tries to perform a TLS handshake (`sslsock.do_handshake()`) with a 3-second timeout.
    *   There are several possible outcomes here:
        *   **TLS Handshake Success:** The server completed the TLS handshake. The script notes this (`expects_tls = True`), prints a success message, closes the SSL socket (`sslsock`, which also closes `original_sock`), and prepares to make an HTTPS request.
        *   **TLS Handshake Failure (SNI Error):** The handshake fails specifically because the server didn't recognize the name (often happens when using an IP address directly). The script notes this (`try_https_despite_sni_error = True`), prints the specific error, explicitly closes the original socket (as it might be in a weird state), and prepares to *still try* an HTTPS request using `hrequests` (since some servers might respond despite the SNI issue).
        *   **TLS Handshake Failure (Other Error or Timeout):** The handshake fails for reasons other than SNI, or it times out. The script notes this (`tls_check_failed = True`), prints the error, and prepares to treat the service as non-TLS (e.g., plain HTTP). It will close the original socket later before attempting a new connection.

4.  **Service Interaction (Based on TLS Check Outcome):**
    *   **Scenario A: If TLS Handshake Succeeded (`expects_tls` is True):**
        *   It attempts an HTTPS GET request to `https://{ip_address}:{tcp_port}` using `hrequests`, disabling SSL certificate verification (`verify=False`).
        *   It prints the details of the `hrequests` response (status code, headers, content snippet, etc.) or any error encountered during the request.
    *   **Scenario B: If TLS Handshake Failed with SNI Error (`try_https_despite_sni_error` is True):**
        *   It *first* attempts an HTTPS GET request to `https://{ip_address}:{tcp_port}` using `hrequests` (like in Scenario A).
        *   If this HTTPS request succeeds, it prints the response details.
        *   If this HTTPS request *fails*, and the error specifically mentions "unrecognized name" again (indicating the server *really* doesn't like the IP for HTTPS), it *then* falls back and attempts a plain HTTP GET request to `http://{ip_address}:{tcp_port}` using `hrequests`. It prints the HTTP response details or any fallback error.
        *   If the initial HTTPS request fails for a *different* reason, it just prints that error and doesn't attempt the HTTP fallback.
    *   **Scenario C: If TLS Handshake Failed Generally (`tls_check_failed` is True):**
        *   It explicitly closes the `original_sock` used for the failed TLS attempt.
        *   It attempts to establish a *new*, plain TCP connection (`socket.create_connection`).
        *   If the reconnection fails, it prints an error.
        *   If the reconnection succeeds:
            *   It tries to receive a banner (initial data sent by the server like SSH version) using `sock.recv(1024)` with a 3-second timeout.
            *   If a banner *is* received, it's decoded and printed.
            *   If no banner is received (or it times out), it assumes the service requires a client request (like HTTP). It then attempts an HTTP GET request to `http://{ip_address}:{tcp_port}` using `hrequests`. It prints the response details or any error.

5.  **Cleanup:**
    *   The `finally` block executes regardless of success or failure within the `try` block.
    *   It checks which socket reference might still exist (`sock` from a reconnection or `original_sock` if the initial connection failed early) and attempts to close it cleanly. This prevents resource leaks.

6.  **Final Output:**
    *   The script prints "### --- Port Check Logic End --- ###".
    *   The `main` function returns 0 on success or 1 on error. The script exits with this code.
