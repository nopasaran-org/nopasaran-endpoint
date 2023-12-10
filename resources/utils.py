def get_api_base_url(host, port):
    # Determine the scheme (HTTP or HTTPS) based on the port number.
    scheme = "https" if port == 443 else "http"

    # Construct the full API URL with the determined scheme and port.
    api_url = f"{scheme}://{host}:{port}/"

    return api_url