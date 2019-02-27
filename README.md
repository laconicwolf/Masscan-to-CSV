# Masscan-XML-to-CSV
Converts the Masscan XML output option (-oX) to a csv format, and other useful functions. This code is based on my [Nmap XML parser](https://github.com/laconicwolf/Nmap-Scan-to-CSV), and has only been tested with masscan using standard forced options and with and without the --banner option.

## Usage

### Convert masscan xml output to csv file
`python3 masscan_xml_parser.py -f masscan_scan.xml -csv masscan_scan.csv`

### Display scan information to the terminal
`python3 masscan_xml_parser.py -f masscan_scan.xml -p`

### Display only IP addresses
`python3 masscan_xml_parser.py -f masscan_scan.xml -ip`

### Display IP addresses/ports in URL friendly format
> Displays in format http(s)://ipaddr:port if port is a possible web port

`python3 masscan_xml_parser.py -f masscan_scan.xml -pw`

### Display least common open ports
> Displays the 10 least common open ports

`python3 masscan_xml_parser.py -f masscan_scan.xml -lc 10`

### Display most common open ports
> Displays the 10 most common open ports

`python3 masscan_xml_parser.py -f masscan_scan.xml -mc 10`

### Display only IP addresses with a specified open port
> Displays only IP addresses where port 23 is open

`python3 masscan_xml_parser.py -f masscan_scan.xml -fp 23`
