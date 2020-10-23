ShodanGeoCheck is a tool designed to find vulnerable IP addresses in a given geographic area. IPs are identified by open
ports and then cross-referenced with AbuseIPDB to see if the IPs have been reported as being involved in malicious activity.
  
A report is generated in a CSV file. The CSV also includes URLs for the Shodan/AbuseIPDB reports for more detail. 

##### Requirements:

1. Shodan API key (basic membership one will be fine, but is limited to returning 100 results at a time).
2. AbuseIPDB key (free membership allows you to query up to 1000 IPs per day)
3. Python 3.8 (this will probably work on earlier versions but I haven't tested it).

##### Setup

Clone the repository. 

`$ git clone https://github.com/nixintel/ShodanGeoCheck`

Install the requirements:

`$ cd ShodanGeoCheck`  
`$ pip install -r requirements.txt`

The program expects to find the necessary API keys in a hidden `.env` file in the same directory as the program. 
`settings.py` checks the `.env` file for the API keys and loads them. The program will exit with an error message if 
they are not present.  

There is a `.env.example` file in this repository. You just need to add your own keys and rename the file to `.env`

Copy and rename the `.env.example`file:

`$ mv .env.example .env`  

Then edit the file:  

`nano .env`

Update the file with the following lines:

`SHODAN_KEY='your Shodan API key goes here'`  
`AIPDB_KEY='your Abuse IPDB key goes here'`

Ctrl + X to save changes and exit.

##### Usage

```usage: main.py [-h] (-l LOCATION | -f FILE) -p PORT -c COUNTRY -o OUTPUT

Queries Shodan to find vulnerable ports in a specific geographic area.

optional arguments:
  -h, --help            show this help message and exit
  -l LOCATION, --location LOCATION
                        Specify a city e.g London (not case-sensitive)
  -f FILE, --file FILE  Input file to load multiple locations. Must be one per line. See example.txt
  -p PORT, --port PORT  Specify a port e.g. 3389. Separate multiple ports with a comma e.g. 3389,445,22
  -c COUNTRY, --country COUNTRY
                        Specify a country with two-letter code e.g. GB
  -o OUTPUT, --output OUTPUT
                        Output file. Select filename and path for results csv

```
The script requires a port, country, output file name (for CSV file) and either a location name or list of lcoation names.

##### Examples

Query a city for IPs with port 3389 exposed:

`$ python main.py -p 3389 -l York -c GB -o 3389ipsYork.csv`

The program runs as follows:

```
Querying Shodan...
73 IPs matched your query
Checking IPs against AbuseIPDB...
Merging datasets...
Creating report, this may take some time...
Report saved as 3389ipsyork.csv

```
Queries for multiple ports can be separated by a comma:

`$ python main.py -p 3389,445 -l York -c GB -o vulnerableips-york.csv`

Multiple locations can be checked at once by loading a list of locations from a file. 
The file must have one location per line. Location names with multiple words need to be enclosed in `""` marks.
  
E.g. `Manchester` is fine but `Milton Keynes` will throw an error and needs to be listed as `"Milton Keynes"`. I'll get round to fixing this one day.

An example of the format is in the `example.txt` file in this repository.

##### Bugs and limitations

The main limitations of this program are connected to Shodan's API. With a basic membership API key Shodan will only return a maximum of 100 results, even if the query reports a higher number of matches.  
For this reason when querying multiple locations it might be better to break it up into smaller queries to avoid missing out results.

When querying for multiple ports e.g. `-p 3389,445` Shodan sees this as OR not AND, so the same IP might appear more than once.

