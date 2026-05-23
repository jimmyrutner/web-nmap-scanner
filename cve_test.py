import json, requests

def cve_data(product, version):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    combined_keyword = f"{product} {version}"

    paramSearch = {
        'keywordSearch': combined_keyword,
        'resultsPerPage': 15
    }


    try:
        
        print(f'Searching for CVEs with keyword {combined_keyword}...')
        response = requests.get(url, params=paramSearch, timeout=10)
        results = []

        if response.status_code == 200:
            data = response.json()

            for data_id in data['vulnerabilities']:
                metric_list = data_id['cve']['metrics']
                
                if 'cvssMetricV31' in metric_list:
                    cvss_marks = metric_list['cvssMetricV31'][0]['cvssData']['baseScore']
                elif 'cvssMetricV2' in metric_list:
                    cvss_marks = metric_list['cvssMetricV2'][0]['cvssData']['baseScore']
                else:
                    cvss_marks = "No record"

                description = data_id['cve']['descriptions']
                desc_text = "No description available."

                if description:
                    en_desc = next((d for d in description if d['lang'] == 'en'), None)
                    desc_text = en_desc['value'] if en_desc else description[0]['value']

                cve_items = {
                    'cve_id': data_id['cve']['id'],
                    'score': cvss_marks,
                    'description': desc_text
                }
                results.append(cve_items)

            results.sort(key=lambda x: x.get('cve_id', ''), reverse=True)
        
        else:
            print(f"API Error: Received status code {response.status_code}")
        
        return results
    
    except Exception as e:
        print(f"API Error: {e}")
        return []
    
#if __name__ == "__main__":
    # Test guna idea baru kau!
    print("=== UJI CVE_DATA FUNCTION ===")
    print("Masukkan nama produk dan version (cth: 'Apache 2.4.49'):")
    user_input = input().split()
    product = user_input[0] if user_input else ""
    version = " ".join(user_input[1:]) if len(user_input) > 1 else ""
    hasil_test = cve_data(product, version)
    print("\n=== HASIL CARIAN ===")
    for cve in hasil_test:
        print(f"ID: {cve['cve_id']} | Score: {cve['score']} | Description: {cve['description']}")