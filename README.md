# Nmap-XML-Parser
Converts Nmap XML output to csv file, and other useful functions

## Usage

### Convert Nmap output to csv file
`python3 nmap_xml_parser.py -f nmap_scan.xml -csv nmap_scan.csv`

### Display scan information to the terminal
`python3 nmap_xml_parser.py -f nmap_scan.xml -p`

### Display only IP addresses
`python3 nmap_xml_parser.py -f nmap_scan.xml -ip`

### Display IP addresses/ports in URL friendly format
> Displays in format http(s)://ipaddr:port if port is a possible web port

`python3 nmap_xml_parser.py -f nmap_scan.xml -pw`

### Display least common open ports
> Displays the 10 least common open ports

`python3 nmap_xml_parser.py -f nmap_scan.xml -lc 10`

### Display most common open ports
> Displays the 10 most common open ports

`python3 nmap_xml_parser.py -f nmap_scan.xml -mc 10`
