# PUPLER
Network Toolkit

# IP Toolkit

The IP Toolkit is a Python command-line tool that provides various network analysis and information retrieval functionalities related to IP addresses and domains. It allows you to perform tasks such as IP scanning, port scanning, DNS lookup, traceroute, Whois lookup, geolocation, subnet calculation, IP reputation check, and more.

## Features

- Scan IP addresses and retrieve information such as country, city, ISP, latitude, and longitude.
- Perform port scanning using different scan types (simple, comprehensive, medium).
- Conduct DNS lookup to retrieve DNS records associated with a domain.
- Perform traceroute to track the path packets take from source to destination.
- Perform Whois lookup to retrieve domain registration information.
- Conduct reverse DNS lookup to find the domain associated with an IP address.
- Perform GeoIP lookup to retrieve geolocation information (country, city, ISP, latitude, longitude) for an IP address.
- Calculate subnet details (network address, broadcast address, netmask, number of hosts) for an IP address and subnet mask.
- Check the reputation of an IP address using the AbuseIPDB API.
- Perform IP geolocation using the ipinfo.io service.
- Calculate IP ranges within a given range of IP addresses.
- Lookup MAC address associated with an IP address on the local network.
- Retrieve Autonomous System Number (ASN) and organization information for an IP address.
- Map IP address to associated services using the Shodan API.
- Check if an IP address is blacklisted using the AbuseIPDB API.
- Conduct custom IP traffic analysis (customizable by the user).

## Requirements

- Python 3.x
- Dependencies: `requests`, `argparse`, `socket`, `readline`, `dns.resolver`, `whois`, `ipaddress`, `json`, `urllib.request`, `colorama`, `tqdm`

## Installation

1. Clone the repository:

```shell
git clone https://github.com/your-username/ip-toolkit.git
```

    Navigate to the project directory:
```shell
cd ip-toolkit
```

    Install the required dependencies:
```shell
pip install -r requirements.txt
```

##Usage

Run the IP Toolkit tool with the following command:

```shell
python ip-toolkit.py
```

You will be presented with a menu displaying different options for performing various network analysis tasks. Enter the corresponding number to select an option and follow the prompts to provide the required information (e.g., IP address, domain name, etc.). The tool will display the results of the selected operation.
Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.
License

This project is licensed under the MIT License.
