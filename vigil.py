import argparse
import sys
from urllib import response
import requests
import json
from texttable import Texttable

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
parser.add_argument('-p', '--platform', help='Platform mobile yang ingin dicari (default = android)', choices=['android', 'ios', 'iphone_os', 'ipad_os'],
                    dest='virtualMatchString', default='android')
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

# penyesuaian untuk platform
# ios -> iphone_os dan ipad_os
all_args['virtualMatchString'] = 'cpe:2.3:a:*:*:*:*:*:*:*:' + all_args['virtualMatchString'] + ':*:*'

# Ambil args yang sudah diinput saja dan membangun url berisi query ke API
input_args = {}
first_arg_passed = False
for key in all_args:
    if (all_args[key] != None):
        # print('ini yg diinput', key, all_args[key], base_api_url)
        base_api_url = base_api_url + ('&' if first_arg_passed else '?') + key + '=' + all_args[key]
        # print(base_api_url)
        first_arg_passed = 1

# Search date
if all_args['year'] != None:
    print('year tidak sama dengan None')
    print(all_args['year'])
    base_api_url = base_api_url + '&pubStartDate=' + all_args['year'] + '-01-01T00:00:00.000&pubEndDate=' + all_args['year'] + '-12-31T00:00:00.000'

# print(base_api_url)

# Menembak API sekaligus mengecek apakah terhubung jaringan/internet
try:
    response = requests.get(base_api_url, timeout=10)
except:
    print("Terdapat kendala jaringan, mohon coba lagi.")
    sys.exit(1)

# Menilai response API
if (response.status_code == 404):
    print('(404) CVE tidak ditemukan.')
    sys.exit(1)
else:
    json_response = response.json()
    if json_response['vulnerabilities'] == []:
        print('Tidak ada hasil.')
    else:
        data = []
        i = 0
        t = Texttable()
        t.add_row(['', 'CVE ID', 'Description', 'Publish Date', 'CWE ID'])
        # t.add_row(['1', 'CVE-2023-3840', 'A vulnerability in the HPE Aruba Networking Virtual Intranet\xa0Access (VIA) client could allow malicious users to overwrite\xa0arbitrary files as NT AUTHORITY\\SYSTEM. A successful\xa0exploit could allow these malicious users to create a\xa0Denial-of-Service (DoS) condition affecting the Microsoft\xa0Windows operating System boot process.'])
        cve_details = json_response['vulnerabilities']
        for cve in cve_details:
            t.add_row([
                i,
                cve['cve']['id'],
                cve['cve']['descriptions'][0]['value'],
                cve['cve']['published'],
                cve['cve']['weaknesses'][0]['description'][0]['value'] if 'weaknesses' in cve['cve'] else '-'
            ])

            i+=1

            data.append({
                'CVE': cve['cve']['id'],
                'Description': cve['cve']['descriptions'][0]['value'],
                'Publish Date': cve['cve']['published'],
                'CWE': cve['cve']['weaknesses'][0]['description'][0]['value'] if 'weaknesses' in cve['cve'] else '-'
            })
            # print(json.dumps(cve['cve']['id'], indent=1, sort_keys=True))
        print(t.draw())

# sys.exit(0)


# contoh CVE code CVE-2023-41993

# python3 vigil.py -c CVE-2023-41993
# python3 vigil.py -k instagram
