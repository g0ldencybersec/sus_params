import requests
from bs4 import BeautifulSoup
import html.parser

reportUrls = set()
session = requests.session()

url = f"https://bugcrowd.com:443/crowdstream.json?page=1&filter_by=disclosures"
cookies = {
    "_crowdcontrol_session": "RHhtclB5NWFxNlZieklqRWVvTVVkRnpOYlo3Ni9GcDJlR0lIWEpyY2daL2owUEp5QjBHQW5JQ01iSzFBcW5sN1Y1dy91MTlaSk9DZWUzRjR6NzhQVG14TERCak5OYkhWRWRDVm82Qm9xM3RHN29zR3NtZWlHQlRFZCtudnI2SDZXeW9vN2ZqVlhrOHFwbmZzWmtWNWREd3ltSXNlS2hPWi9rU1BPVEphTFZyaEh4YVdtcmc0TG5VOGVMckpYRjFQWDVkYmRSZk1nT1BLeGtodmU3dHBPRjNUUjcyNWVVOGpvNkgwbUlqNzRmWUkwb0NuZTI1WHJTbmRsbHpmSG8vcVVzZDNKcis2dnQzcVpmMHhHMnYvdTRnMG1HSk8zYW1IYnIxMkFYUllxN3VWb3VqVXdpRFhxdEdFenkxZFpJUDBTOUZPTGhZNmR3UWFIeXNwcEFBUHNTWENVUC9uQnJJblh0dG1ESTZBM1lsc3h1T2NqZ0FrNHVrblVVMWVZVHRDc3F4TVg3dXRqWE5obXhSeUt4WEZGSmd5QXcvVjFoUDVXTUhVWk9WOTV3ajVSc0NOVGZDUkh0cDZWSXdldFhKOS0tejFOQ0RyMkt0ZE8rMUdaanI3ejI1QT09--82978ffd082dee1b2b7ffb3858e6fbf47fa155c5", 
}
headers = { 
    "Content-Type": "application/json", 
    "X-Csrf-Token": "Kx1wcrdym6gxCPFOhMm+16Ml1oaNQBE//hKezZYM4GdRrlVTUlxgqudiOMp8T93RVoSW3FEJqDBdeZlllDUSyA=="
}
response = session.get(url, headers=headers, cookies=cookies)
total_pages = response.json()['pagination_meta']['total_pages']

pageNum = 1
while pageNum <= total_pages:
    url = f"https://bugcrowd.com:443/crowdstream.json?page={pageNum}&filter_by=disclosures"
    print(f"grabbing {url}...")
    response = session.get(url, headers=headers, cookies=cookies)

    for result in response.json()['results']:
        reportUrls.add(result['disclosure_report_url'])

    pageNum = pageNum + 1

print(f"Found {len(reportUrls)} report URLs!")

for report in reportUrls:
    response = session.get("https://bugcrowd.com"+report, cookies=cookies, headers=headers)
    
    soup = BeautifulSoup(response.content, "html.parser")
    results = soup.find_all("section",class_="col-md-9")
    print(results)