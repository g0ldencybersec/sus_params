import requests
import json

reportUrls = set()
session = requests.session()

graphql_url = "https://hackerone.com:443/graphql"
cookies = {
  "__Host-session": "aXBIbjB1STREL3V6RTBuaTY2blRWUHh1N2tXSkhqbjhGU2daVnZiSFh0L3BZSkJLUk5Nd0tNdVp5OFFnVGtobDJIeHo0eEJQSTNlMGxIMVlCSkZqM1Y1NytGa0dpN2lPVGVJT2FtUS9lTXhpOXBlb2VnWmdhSERDUW5mM0FyUGthWktZU1JHN1VWUytxU1RTbjZVcWFoa2FPVk9BenJjOC9WelNwNnhpQkNtNzAvQ3ltN05rMjVVMXloaVhpTDNaZGdIdmtYTStGV0tMWnZLd0ZIRExqOWRMcDZsajVtaUh6ZFVtUFNQK0VTb1d6ZTZtZzh3YjdQVzVZS0lKTUpEOEFXQXdmN2sza0J1NElvaGM5VlByTTdDLzJqZlFSOTlteG0wWlozZ3hEOUdDckpteWZNR3U2amhhUU9MRlZvbU5LNzZYYXhRRVUvdC9FQmxNSUxQZmkycnN0OS9MNG5Ha3pMLzFLUmdZRUtkZm52d1QxeVFIVlpQbmVyVWJ5eHJxcEZla3ltL2hXVnlLZ1h5bGFrSHVQTklRRkVmMEZaZmNreTJ2RWtTU1Rja2hNajJFS1pKN0VOek9VT0tGd3JjRHZRTWgvd3NZeFh4b0lhNFJ3WUNtNFUrOVgvd1ZScTBTU3RLZVQreGtKNFJ3ZU5YZUQzV3d5VWx1Q1dJM1crTFBwS3FQQjE0dzRrcDRlMTM3QWlpZ0NSYXRocElJODkxRWZudW8rY25Jd2dvaGs5OFo1SmhFclMxTDJheHpudUQyV0dJNzJ3bEFUZS80Vk9iZDJ4WHdJTjVnY21DNTYrK1Zwd1NML2hwcEFYR2dORnA0am9OUHNvT2xqSlVZZzNBLzJGS3FML21RWXhwTG9MVzhZalV5R1BiNHZzNE9hOG5UZzh5SXhDWUhYNHM9LS1icmhNRlVhZGlLZ1BYSGZpS2NsR05BPT0%3D--97ba3ea41d896ed935aab5e393c12d8d7b0fb074"}
headers = {"Content-Type": "application/json", "X-Csrf-Token": "bvyy75cEacX1ywOPQdOx1Xqf8dAztwxkNUnS9aKg20OUCkvGuc8Urs9R+MhvIWmcDR5iIo2los4cS7gTJ2VWNw=="}
query_string = """
query HacktivityPageQuery($querystring: String, $orderBy: HacktivityItemOrderInput, $secureOrderBy: FiltersHacktivityItemFilterOrder, $where: FiltersHacktivityItemFilterInput, $count: Int, $cursor: String) {
  me {
    id
    __typename
  }
  hacktivity_items(
    first: $count
    after: $cursor
    query: $querystring
    order_by: $orderBy
    secure_order_by: $secureOrderBy
    where: $where
  ) {
    ...HacktivityList
    __typename
  }
}

fragment HacktivityList on HacktivityItemConnection {
  pageInfo {
    endCursor
    hasNextPage
    __typename
  }
  edges {
    node {
      ... on HacktivityItemInterface {
        id
        databaseId: _id
        __typename
      }
      __typename
    }
    ...HacktivityItem
    __typename
  }
  __typename
}

fragment HacktivityItem on HacktivityItemUnionEdge {
  node {
    ... on HacktivityItemInterface {
      id
      type: __typename
    }
    ... on Disclosed {
      id
      ...HacktivityItemDisclosed
      __typename
    }
    __typename
  }
  __typename
}

fragment HacktivityItemDisclosed on Disclosed {
  id
  report {
    id
    databaseId: _id
    title
    substate
    url
    __typename
  }
  total_awarded_amount
  currency
  __typename
}
"""

query_json={
  'operationName': 'HacktivityPageQuery',
  'variables': {
    'querystring': '',
    'where':{
      'report':{
        'disclosed_at':{
          '_is_null': False
        }
      }
    },
    'orderBy':{
      'field':'popular',
      'direction':'DESC'
    },
    'secureOrderBy':None,
    'count': 100
  },
  'query':query_string
}


hasNextPage = True
count = 1
while hasNextPage:
  response = session.post(graphql_url, headers=headers, cookies=cookies, json=query_json)
  respJson = response.json()

  pageInfo =respJson['data']['hacktivity_items']['pageInfo']
  if pageInfo['hasNextPage'] is False:
    hasNextPage = False
  
  edges = respJson['data']['hacktivity_items']['edges']
  for edge in edges:
    try:
      reportUrls.add(edge['node']['report']['url'])
    except KeyError:
      continue

  print(f"I have captured {len(reportUrls)} report urls now")

  if hasNextPage:
    count = count + 1
    print(f"Going to cursor: {pageInfo['endCursor']}")
    query_json={
      'operationName': 'HacktivityPageQuery',
      'variables': {
        'querystring': '',
        'where':{
          'report':{
            'disclosed_at':{
              '_is_null': False
            }
          }
        },
        'orderBy':{
          'field':'popular',
          'direction':'DESC'
        },
        'secureOrderBy':None,
        'count': 100,
        "cursor":pageInfo['endCursor']
      },
      'query':query_string}
  else:
    print("Report Gathering Completed!")
    hasNextPage = False

print(f"Found {len(reportUrls)} report urls")

vuln_list = []
for url in reportUrls:
  response = session.get(url+".json", headers=headers, cookies=cookies)
  if response.status_code == 200:
    new_vuln_info = {"id": response.json()['id'], "title":response.json()['title'], "vulnerability_information": response.json()['vulnerability_information'], "content": []}
    if "weakness" in response.json().keys():
      new_vuln_info['weakness'] = response.json()['weakness']
    else:
      new_vuln_info['weakness'] = {}
    if "summaries" in response.json().keys():
      for summary in response.json()['summaries']:
        if "content" in summary.keys():
          new_vuln_info['content'].append(summary['content'])
    vuln_list.append(new_vuln_info)
  else:
    print(f"NONE 200 sc on {url}")
    break

with open('json_files/vulns.json', 'w') as fout:
  json.dump(vuln_list, fout, indent=4)
  fout.close()

## Run processor