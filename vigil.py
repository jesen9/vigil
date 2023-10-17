import argparse
import keyword
import sys
from urllib import response
import requests
import json

parser = argparse.ArgumentParser(
    description='Vigil merupakan script yang menggunakan OSINT untuk mencari laporan-laporan kelemahan dalam '
                'aplikasi mobile.',
    epilog='Informasi yang didapat merupakan informasi yang didapat dari berbagai sumber. Mohon gunakan '
           'informasi-informasi tersebut dengan bijak.')

parser.add_argument('-c', '--code', help='Mencari laporan berdasarkan kode CVE', dest='CVE_code')
# parser.add_argument('-s', '--sum', dest='accumulate', action='store_const',
#                    default=max,
#                    help='sum the integers (default: find the max)')
parser.add_argument('-y', '--year', help='Tahun versi OS, Aplikasi, atau kode CVE')
parser.add_argument('-p', '--platform', help='Platform mobile yang ingin dicari', choices=['android', 'ios'],
                    dest='botol')
parser.add_argument('-l', '--list', help='List', action='store_const', const=True, default=False)
parser.add_argument('-s', '--source', help='API yang dijadikan sumber data', dest='api_source')
parser.add_argument('-k', '--keyword', help='cari dengan kata kunci tertentu', dest='keyword')

# Print help apabila tidak diberi argumen (dipanggil scriptnya saja)
if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

args = parser.parse_args()

print(args.CVE_code)
base_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Process args
if args.CVE_code:
    cve_api_url = base_api_url + "?cveId=" + args.CVE_code
    print(cve_api_url)
    response = requests.get(cve_api_url)
    # print(type(response.json())) # type is list

    # response.json() petiknya cmn ', bukan ", jadi harus dilewatin json.dumps()
    json_response = response.json()

    # for pretty print. ex: json.dumps(json_response, indent=4, sort_keys=True)
    json_dumps = json.dumps(json_response)
    json_dupms_beautify = json.dumps(json_response, indent=1, sort_keys=True)
    jsonparsed = json.loads(json_dumps)
    # print(type(jsonparsed)) # type is list
    # print('json response')
    # print(type(json_response))  # type is list
    #
    # print('\n')
    # print(json_response)  # petik satu
    #
    # print('\n')
    # print(json_dumps)  # petik dua
    #
    # print('\n')
    # print(json_dupms_beautify)  # petik dua, rapih dgn indentation
    #
    # print('\n')
    # print(jsonparsed)  # petik satu
    # print(type(jsonparsed))  # type is dict
# keknya ini deh tipe data yg cocok utk json

# menggunakan json response seperti halnya dictionary di python
    print('\n')
    for key in json_response:{
        print(key,":",json_response[key])
    }
# yg ini error -> TypeError: list indices must be integers or slices, not dict

# loaded = json.loads(str(response.json()))
# print(loaded)
elif args.keyword:
    # cve_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=instagram"
    cve_api_url = base_api_url + "?keywordSearch=" + args.keyword
    print(cve_api_url)

    response = requests.get(cve_api_url)
    json_response = response.json()

    # menggunakan json response seperti halnya dictionary di python
    # print(json.dumps(json_response, indent=1, sort_keys=True))
    print('\n')
    for key in json_response: {
        print(key, ":", json_response[key])
    }

# print(args.CVE_code)
# print(args)

# contoh CVE code CVE-2023-41993

# python3 coba1.py -c CVE-2023-41993
# python3 coba1.py -k instagram
