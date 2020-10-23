import shodan
import json
import pandas as pd
import settings as s
import argparse
import sys
import requests


def get_locations(file):
    with open(file, 'r') as f:
        lines = f.readlines()
        lines = ''.join([str(i) for i in lines])
        lines = lines.replace('\n', ',')
        lines = lines.rstrip(',')
        lines = lines.lower()
        query_string = lines

        return query_string

def build_query(port, loc, country):

    query = 'port:'+ port + "+city:" + loc + "+country:"+str(country)
    return query


def shodan_query(key,query):

    print('Querying Shodan...')

    try:

        handler = shodan.Shodan(key)

        result = handler.search(query)

        t = result['total']
        print(str(t) + ' IPs matched your query')



    except Exception as e:
        print('Error %s' %e)

    return result



def aipdb_query(ips,key):

    source_ips = ips
    appended_data = []

    try:
        for i in source_ips:

            url = 'https://api.abuseipdb.com/api/v2/check'

            querystring = {
                'ipAddress': str(i),
                'maxAgeInDays': '365'
            }

            headers = {
                'Accept': 'application/json',
                'Key': str(key)
            }

            response = requests.request(method='GET', url=url, headers=headers, params=querystring)

            decodedResponse = json.loads(response.text)
            appended_data.append(decodedResponse['data'])

    except Exception as e:
        print('Error %s' % e)



    df = pd.DataFrame(appended_data)

    df = df[['ipAddress','lastReportedAt', 'abuseConfidenceScore', 'totalReports']]
    return df


def get_ips(source):
    ips = []
    for ip in source['matches']:
        ips.append(ip['ip_str'])

    return ips


def build_shodan_df(source):

    appended_data = []
    for i in source['matches']:
        ip = i['ip_str']
        port = i['port']
        location = i['location']['city']
        time = i['timestamp']
        org = i['org']
        link = 'https://shodan.io/host/'+str(ip)
        abuselink = 'https://www.abuseipdb.com/check/'+str(ip)
        data = [ip, port, location, time, org, link, abuselink]
        appended_data.append(data)

    df = pd.DataFrame(appended_data, columns=['IP address', 'Port', 'Location', 'Time seen (UTC)', 'ISP', 'Shodan Link','AbuseIPDB Link'])
    return df


def merge_dfs(df1, df2):
    frame = [df1, df2]
    df = pd.concat(frame, axis=1)
    cols = ['IP address', 'Port', 'Location', 'Time seen (UTC)', 'ISP', 'Shodan Link','lastReportedAt', 'abuseConfidenceScore', 'totalReports', 'AbuseIPDB Link' ]
    df = df.reindex(columns=cols)
    df = df.rename(columns={'lastReportedAt':'AbuseIPDB Last Report','abuseConfidenceScore':'Abuse Confidence Score','totalReports':'Abuse IPDB Reports (last 365 days)'})
    return df


def create_csv(df, filename):
    print('Creating report, this may take some time...')
    filename = str(filename)
    report = df.to_csv(filename, index=True)
    print('Report saved to ' + filename)
    return report


def main():

    #arguments
    parser = argparse.ArgumentParser(description='Queries Shodan to find vulnerable ports in a specific geographic area.')


    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l', '--location', help='Specify a city e.g London (not case-sensitive)')
    group.add_argument('-f', '--file', help='Input file to load multiple locations. Must be one per line. See example.txt')
    parser.add_argument('-p', '--port', help='Specify a port e.g. 3389. Separate multiple ports with a comma e.g. 3389,445,22' , required=True)
    parser.add_argument('-c', '--country', help='Specify a country with two-letter code e.g. GB', required=True)
    parser.add_argument('-o', '--output', help='Output file. Select filename and path for results csv', required=True)

    args = parser.parse_args()


    port = args.port
    country = args.country
    inputfile = args.file
    savefile = args.output

    if args.location:
        location = args.location

    if args.file:
        location = get_locations(inputfile)

    # Set API keys

    if s.shodan_key == None:
        print('Shodan API key is not present in .env file. Exiting.')
        sys.exit()
    else:
        shodan_key = s.shodan_key

    if s.aipdb_key == None:
        print('Abuse IPDB API key is not present in .env file. Exiting.')
        sys.exit()
    else:
        abuseipdb_key = s.aipdb_key

    # build query string

    query = build_query(port, location, country)

    # Shodan query

    raw_hits = shodan_query(shodan_key, query)

    raw_ips = get_ips(raw_hits)

    shodan_df = build_shodan_df(raw_hits)

    # Take IPs form Shodan matches and query with AbuseIPDB

    aipdb_df = aipdb_query(raw_ips, abuseipdb_key)

    # Concat shodan df and abuse df, convert to csv

    joined_df = merge_dfs(shodan_df, aipdb_df)
    create_csv(joined_df, savefile)

main()