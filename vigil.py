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

# 'dest' di sini menyesuaikan params dari API NVD
parser.add_argument('-c', '--code', help='Mencari laporan berdasarkan kode CVE', dest='cveId')
# parser.add_argument('-s', '--sum', dest='accumulate', action='store_const',
#                    default=max,
#                    help='sum the integers (default: find the max)')
parser.add_argument('-y', '--year', help='Tahun versi OS, Aplikasi, atau kode CVE')
parser.add_argument('-p', '--platform', help='Platform mobile yang ingin dicari', choices=['android', 'ios'],
                    dest='platform')
# parser.add_argument('-l', '--list', help='List', action='store_const', const=True, default=False)
# parser.add_argument('-s', '--source', help='API yang dijadikan sumber data', dest='api_source')
parser.add_argument('-k', '--keyword', help='cari dengan kata kunci tertentu', dest='keywordSearch')

# Print help apabila tidak diberi argumen (dipanggil scriptnya saja)
if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

# Parse args dan buat iterable
all_args = vars(parser.parse_args())

base_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Ambil args yang sudah diinput saja
input_args = {}
first_arg_passed = False
for key in all_args:
    if (all_args[key] != None):
        # print('ini yg diinput', key, all_args[key], base_api_url)
        base_api_url = base_api_url + ('&' if first_arg_passed else '?') + key + '=' + all_args[key]
        # print(base_api_url)
        first_arg_passed = 1

print(base_api_url)

# Menembak API sekaligus mengecek apakah terhubung jaringan/internet
try:
    response = requests.get(base_api_url)
except:
    print("Tidak terhubung jaringan.")
    sys.exit(1)

if (response.status_code == 404):
    print('(404) CVE tidak ditemukan.')
    sys.exit(1)
else:
    json_response = response.json()
    if json_response['vulnerabilities'] == []:
        print('Tidak ada hasil.')
    else:
        cve_details = json_response['vulnerabilities'][0]['cve']
        print(json.dumps(cve_details, indent=1, sort_keys=True))


    # print(type(response.json())) # type is list

    # response.json() petiknya cmn ', bukan ", jadi harus dilewatin json.dumps()



sys.exit(0)



# Process args
if args.CVE_code:
    cve_api_url = base_api_url + "?cveId=" + args.CVE_code
    response = requests.get(cve_api_url)
    
    if (response.status_code == 404):
        print('CVE tidak ditemukan.')
        sys.exit(1)
    # print(type(response.json())) # type is list

    # response.json() petiknya cmn ', bukan ", jadi harus dilewatin json.dumps()
    json_response = response.json()
    cve_details = json_response['vulnerabilities'][0]['cve']
    
    # for pretty print. ex: json.dumps(json_response, indent=4, sort_keys=True)
    json_dumps = json.dumps(json_response)
    json_dupms_beautify = json.dumps(json_response, indent=1, sort_keys=True)
    jsonparsed = json.loads(json_dumps)
    # print(json_response)  # petik satu
    # print(jsonparsed)  # petik satu
    # print(json_dumps)  # petik dua
    # print(json_dupms_beautify)  # petik dua, rapih dgn indentation
    # print(type(jsonparsed)) # type is list
    # print(type(json_response))  # type is list
    # print(type(jsonparsed))  # type is dict

# menggunakan json response seperti halnya dictionary di python
    
    # print('\n')
    # for key in json_response:{
    #     print(key,"[::]",json_response[key])
    # }
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

# python3 vigil.py -c CVE-2023-41993
# python3 vigil.py -k instagram
