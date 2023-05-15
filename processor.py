import json
import re


xss_params = {}
idor_params = {}
redirect_params = {}
file_inclusion_params = {}
sqli_params = {}
ssti_params = {}
ssrf_params = {}

def extract_url_params(desc):
    url_pattern = re.compile(r'(https?:\/\/(?:www\.|(?!www))[^\s.]+\.[^\s]{2,})')
    params_pattern = re.compile(r'\?(.*)')
    parameter_names = []
    urls = re.findall(url_pattern, desc)
    for url in urls:
        match = re.search(params_pattern, url)
        if match:
            params_string = match.group(1)
            params_list = re.findall(r'(\w+)=', params_string)
            parameter_names.extend(params_list)
    return parameter_names

def extract_request_params(desc):
    pattern = re.compile(r'(POST|GET|PUT|PATCH|DELETE)\s+([\w/]+)(?:\?([^ ]+))?\s+HTTP/\d\.\d\s+(?:.*(?:\n|\r\n))+(.*)')
    parameter_names = []


    matches = re.findall(pattern, desc)

    for match in matches:
        method = match[0]
        url = match[1]
        url_params = {}
        if match[2]:
            for param in match[2].split('&'):
                if '=' in param:
                    key_value = param.split('=')
                    key = key_value[0]
                else:
                    key = param
                url_params[key] = None
        body = match[3]
        body_params = {}
        if 'Content-Type: application/json' in body:
            body_params = {key: None for key in json.loads(body.split('\n')[-1]).keys()}
        elif 'Content-Type: application/x-www-form-urlencoded' in body:
            for param in body.split('\n')[-1].split('&'):
                if '=' in param:
                    key_value = param.split('=')
                    key = key_value[0]
                else:
                    key = param
                body_params[key] = None
        elif 'Content-Type: multipart/form-data' in body:
            boundary = re.search(r'boundary=(.+)', body).group(1)
            for part in body.split('--' + boundary)[1:-1]:
                name_match = re.search(r'name="([^"]+)"', part)
                if name_match:
                    name = name_match.group(1)
                    body_params[name] = None
        if 'Content-Type: application/x-www-form-urlencoded' in body:
            params = body.split('&')
            for param in params:
                name = param.split('=')[0]
                body_params[name] = None

        # print(f"HTTP {method} {url}")
        parameter_names.extend(list(url_params.keys()))
        parameter_names.extend(list(body_params.keys()))
    return parameter_names

def extract_text_params(desc):
    pattern = re.compile(r"\b(\w+)\s*(?:param|parameter)\b")
    garbage = ['get', 'post', 'put', 'patch', 'the', 'this', 'is', 'its', 'vulnerable', 'what', 'of', 'a', 'as', '1st', '2nd', '3rd', '4th']
    

    params = re.findall(pattern, desc)
    # Create new list of parameter names without methods
    parameter_names = [param for param in params if param.lower() not in garbage]

    return parameter_names


def extract_php_params(desc):
    phpParams = re.findall(re.compile("\$_(GET|POST)\[['|\"](.*?)['|\"]]"),str(desc))
    parameter_names = [match[1] for match in phpParams]
    return parameter_names

def export_data():
    with open('json_files/xss.json', 'w') as fout:
        json.dump(xss_params, fout, indent=4)
        fout.close()
    with open('json_files/idor.json', 'w') as fout:
        json.dump(idor_params, fout, indent=4)
        fout.close()
    with open('json_files/redirect.json', 'w') as fout:
        json.dump(redirect_params, fout, indent=4)
        fout.close()
    with open('json_files/file_inclusion.json', 'w') as fout:
        json.dump(file_inclusion_params, fout, indent=4)
        fout.close()
    with open('json_files/sqli.json', 'w') as fout:
        json.dump(sqli_params, fout, indent=4)
        fout.close()
    with open('json_files/ssti.json', 'w') as fout:
        json.dump(ssti_params, fout, indent=4)
        fout.close()
    with open('json_files/ssrf.json', 'w') as fout:
        json.dump(ssrf_params, fout, indent=4)
        fout.close()

if __name__ == "__main__":
    f = open('json_files/vulns.json')
    data = json.load(f)

    for report in data:
        if "xss" in report['title'].lower() or "cross site scripting" in report['title'].lower():
            xss_set = set()
            xss_set.update(extract_url_params(report['vulnerability_information']))
            xss_set.update(extract_request_params(report['vulnerability_information']))
            xss_set.update(extract_text_params(report['vulnerability_information']))
            xss_set.update(extract_php_params(report['vulnerability_information']))
            for content in report['content']:
                xss_set.update(extract_url_params(content))
                xss_set.update(extract_request_params(content))
                xss_set.update(extract_text_params(content))
                xss_set.update(extract_php_params(content))
            for param in xss_set:
                if param not in xss_params.keys():
                    xss_params[param] = 1
                else:
                    xss_params[param] = xss_params[param] + 1
        if "idor" in report['title'].lower():
            idor_set = set()
            idor_set.update(extract_url_params(report['vulnerability_information']))
            idor_set.update(extract_request_params(report['vulnerability_information']))
            idor_set.update(extract_text_params(report['vulnerability_information']))
            idor_set.update(extract_php_params(report['vulnerability_information']))
            for content in report['content']:
                idor_set.update(extract_url_params(content))
                idor_set.update(extract_request_params(content))
                idor_set.update(extract_text_params(content))
                idor_set.update(extract_php_params(content))
            for param in idor_set:
                if param not in idor_params.keys():
                    idor_params[param] = 1
                else:
                    idor_params[param] = idor_params[param] + 1
        if "redirect" in report['title'].lower():
            redirect_set = set()
            redirect_set.update(extract_url_params(report['vulnerability_information']))
            redirect_set.update(extract_request_params(report['vulnerability_information']))
            redirect_set.update(extract_text_params(report['vulnerability_information']))
            redirect_set.update(extract_php_params(report['vulnerability_information']))
            for content in report['content']:
                redirect_set.update(extract_url_params(content))
                redirect_set.update(extract_request_params(content))
                redirect_set.update(extract_text_params(content))
                redirect_set.update(extract_php_params(content))
            for param in redirect_set:
                if param not in redirect_params.keys():
                    redirect_params[param] = 1
                else:
                    redirect_params[param] = redirect_params[param] + 1
        if "lfi" in report['title'].lower() or "rfi" in report['title'].lower() or "file inclusion" in report['title'].lower():
            file_inclusion_set = set()
            file_inclusion_set.update(extract_url_params(report['vulnerability_information']))
            file_inclusion_set.update(extract_request_params(report['vulnerability_information']))
            file_inclusion_set.update(extract_text_params(report['vulnerability_information']))
            file_inclusion_set.update(extract_php_params(report['vulnerability_information']))
            for content in report['content']:
                file_inclusion_set.update(extract_url_params(content))
                file_inclusion_set.update(extract_request_params(content))
                file_inclusion_set.update(extract_text_params(content))
                file_inclusion_set.update(extract_php_params(content))
            for param in file_inclusion_set:
                if param not in file_inclusion_params.keys():
                    file_inclusion_params[param] = 1
                else:
                    file_inclusion_params[param] = file_inclusion_params[param] + 1
        if "sqli" in report['title'].lower() or "sql injection" in report['title'].lower():
            sqli_inclusion_set = set()
            sqli_inclusion_set.update(extract_url_params(report['vulnerability_information']))
            sqli_inclusion_set.update(extract_request_params(report['vulnerability_information']))
            sqli_inclusion_set.update(extract_text_params(report['vulnerability_information']))
            sqli_inclusion_set.update(extract_php_params(report['vulnerability_information']))
            for content in report['content']:
                sqli_inclusion_set.update(extract_url_params(content))
                sqli_inclusion_set.update(extract_request_params(content))
                sqli_inclusion_set.update(extract_text_params(content))
                sqli_inclusion_set.update(extract_php_params(content))
            for param in sqli_inclusion_set:
                if param not in sqli_params.keys():
                    sqli_params[param] = 1
                else:
                    sqli_params[param] = sqli_params[param] + 1
        if "ssti" in report['title'].lower() or "template injection" in report['title'].lower():
            ssti_inclusion_set = set()
            ssti_inclusion_set.update(extract_url_params(report['vulnerability_information']))
            ssti_inclusion_set.update(extract_request_params(report['vulnerability_information']))
            ssti_inclusion_set.update(extract_text_params(report['vulnerability_information']))
            ssti_inclusion_set.update(extract_php_params(report['vulnerability_information']))
            for content in report['content']:
                ssti_inclusion_set.update(extract_url_params(content))
                ssti_inclusion_set.update(extract_request_params(content))
                ssti_inclusion_set.update(extract_text_params(content))
                ssti_inclusion_set.update(extract_php_params(content))
            for param in ssti_inclusion_set:
                if param not in ssti_params.keys():
                    ssti_params[param] = 1
                else:
                    ssti_params[param] = ssti_params[param] + 1
        if "ssrf" in report['title'].lower() or "server side request forgery" in report['title'].lower():
            ssrf_inclusion_set = set()
            ssrf_inclusion_set.update(extract_url_params(report['vulnerability_information']))
            ssrf_inclusion_set.update(extract_request_params(report['vulnerability_information']))
            ssrf_inclusion_set.update(extract_text_params(report['vulnerability_information']))
            ssrf_inclusion_set.update(extract_php_params(report['vulnerability_information']))
            for content in report['content']:
                ssrf_inclusion_set.update(extract_url_params(content))
                ssrf_inclusion_set.update(extract_request_params(content))
                ssrf_inclusion_set.update(extract_text_params(content))
                ssrf_inclusion_set.update(extract_php_params(content))
            for param in ssrf_inclusion_set:
                if param not in ssrf_params.keys():
                    ssrf_params[param] = 1
                else:
                    ssrf_params[param] = ssrf_params[param] + 1

    export_data()


    f.close()