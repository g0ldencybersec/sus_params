import json
import pprint as pprint

f = open('json_files/xss.json')
data = json.load(f)

# Sort the dictionary by its integer values
sorted_dict = dict(sorted(data.items(), key=lambda x: x[1], reverse=True))

# Print the sorted dictionary
print(json.dumps(sorted_dict, indent=4))