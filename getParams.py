import re
import json
from collections import Counter

def is_custom_alnum(s):
    return all(c.isalnum() or c in ['_', '-'] for c in s)

def find_patterns_in_file(file_path):
    # Opening file
    with open(file_path, 'r') as file:
        text = file.read()

    # Pattern 1: In a bullet/dashed list. This looks for lines starting with "- " or "* ".
    pattern1 = re.compile(r"^(?:\-\s|\*\s)(.*)", re.MULTILINE)
    matches_pattern1 = re.findall(pattern1, text)

    # Pattern 2: Inside double quotes, single quotes, or `.
    pattern2 = re.compile(r"[\"'`](.*?)[\"'`]", re.MULTILINE)
    matches_pattern2 = re.findall(pattern2, text)

    # Pattern 3: Inside two / symbols.
    pattern3 = re.compile(r"/(.*?)/", re.MULTILINE)
    matches_pattern3 = re.findall(pattern3, text)

    # Combine the three lists into one
    combined = matches_pattern1 + matches_pattern2 + matches_pattern3

    # Create a new list that only contains elements without a space, not containing '████████', and is alphanumeric + '_' + '-'
    filtered_list = [x for x in combined if ' ' not in x and '█' not in x and is_custom_alnum(x)]

    # Count the occurrences of each element in the filtered list
    count_dict = Counter(filtered_list)

    # Remove the key if it's empty
    count_dict.pop('', None)

    return count_dict

def getParams(file_path, vuln_type):
    result = find_patterns_in_file(file_path)
    # Sort the dictionary by its integer values
    sorted_dict = dict(sorted(result.items(), key=lambda x: x[1], reverse=True))
    # Save the dictionary to a JSON file
    with open(f'output/{vuln_type}.json', 'w') as f:
        json.dump(sorted_dict, f, indent=4)
    f.close()

# XSS
getParams("test/xss-file.txt", "xss")
# SSTI
getParams("test/ssti-file.txt", "ssti")
# SSRF
getParams("test/ssrf-file.txt", "ssrf")
# IDOR
getParams("test/idor-file.txt", "idor")
# FILEINC
getParams("test/fileinc-file.txt", "fileinc")
# SQLI
getParams("test/sqli-file.txt", "sqli")
# REDIRECT
getParams("test/redirect-file.txt", "redirect")
