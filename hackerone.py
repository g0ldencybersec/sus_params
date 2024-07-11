#!/usr/bin/env python3
import json
from argparse import ArgumentParser
from time import sleep
from typing import Generator

import httpx


class HackerOneSession:
    """Client to interact with HackerOne API."""

    def __init__(
        self,
        cookie: str | None = None,
        csrf_token="bvyy75cEacX1ywOPQdOx1Xqf8dAztwxkNUnS9aKg20OUCkvGuc8Urs9R+MhvIWmcDR5iIo2los4cS7gTJ2VWNw==",
        rate_limit_timer=4,
    ):
        """Initialize the HackerOne session.

        :param cookie: HackerOne cookie called __Host-session. Login to HackerOne and capture the cookie.
        :param api_key: HackerOne API key.
        """
        self._cookie = cookie
        self.rate_limit_timer = rate_limit_timer

        self.headers = {
            "Content-Type": "application/json",
            "__Host-session": cookie,
            "X-Csrf-Token": csrf_token,
        }
        self._session = httpx.Client(headers=self.headers, timeout=30)

    @property
    def graphql_url(self):
        return "https://hackerone.com/graphql"

    @property
    def cookie(self) -> str | None:
        return self._cookie

    @cookie.setter
    def cookie(self, cookie: str):
        self._cookie = cookie
        self._session.headers["__Host-session"] = cookie

    @property
    def api_key(self) -> str | None:
        return self._api_key

    @api_key.setter
    def api_key(self, api_key: str):
        self._api_key = api_key
        self._session.headers["Authorization"] = f"Bearer {api_key}"

    def list_report_ids(self, rate_limit_timer=None) -> Generator[str, None, None]:
        """List all hactivity report ids that are disclosed.

        GraphQL taken from:
        https://github.com/g0ldencybersec/sus_params/blob/main/hackerone.py

        :param rate_limit_timer: Time to wait before retrying request.

        :return: Generator of report ids.
        """
        if not rate_limit_timer:
            rate_limit_timer = self.rate_limit_timer

        if not self.cookie:
            raise ValueError("Cookie is required to fetch reports.")

        # Adjusted original query to only return relevant fields
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
        )   {
                ...HacktivityList
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
                    databaseId: _id
                }
            }
        }
        }
        """

        query_json = {
            "operationName": "HacktivityPageQuery",
            "variables": {
                "querystring": "",
                "where": {"report": {"disclosed_at": {"_is_null": False}}},
                "orderBy": {"field": "popular", "direction": "DESC"},
                "secureOrderBy": None,
                "count": 100,
            },
            "query": query_string,
        }

        has_next_page = True
        while has_next_page:
            while True:
                try:
                    response = self._session.post(self.graphql_url, json=query_json)
                except Exception as e:
                    print(f"Error on {query_json}: {e}")
                    sleep(rate_limit_timer)
                    continue

                if response.is_error:
                    print(f"Error on {query_json}: {response.status_code}")
                    sleep(rate_limit_timer)
                    continue
                break

            data = response.json()
            edges = data["data"]["hacktivity_items"]["edges"]

            for edge in edges:
                try:
                    yield edge["node"]["databaseId"]
                    # yield f"{edge['node']['report']['url']}.json"
                except KeyError:
                    continue

            has_next_page = data["data"]["hacktivity_items"]["pageInfo"]["hasNextPage"]
            if has_next_page is False:
                break

            query_json["variables"]["cursor"] = data["data"]["hacktivity_items"][
                "pageInfo"
            ]["endCursor"]

    def list_reports(self, rate_limit_timer=None) -> Generator[dict, None, None]:
        """Retrieve vulnerability reports from HackerOne.

        :param rate_limit_timer: Time to wait before retrying request.

        :return: Generator of reports dictionary represenation.
        """
        if not rate_limit_timer:
            rate_limit_timer = self.rate_limit_timer

        if not self.cookie:
            raise ValueError("Cookie is required to fetch reports.")

        for report_id in self.list_report_ids():
            while True:
                try:
                    response = self._session.get(
                        f"https://hackerone.com/reports/{report_id}.json"
                    )
                except Exception as e:
                    print(f"ERROR - {report_id}: {e}")
                    sleep(rate_limit_timer)
                    continue

                if response.is_error:
                    print(f"ERROR - {report_id}: {response.status_code}")
                    if response.status_code == 429:
                        sleep(rate_limit_timer)
                        continue
                    else:
                        raise
                break

            data = response.json()
            if not data:
                print(f"WARNING - {report_id}: No data found")
                continue

            try:
                report = {
                    "id": data["id"],
                    "title": data["title"],
                    "submitted_at": data["submitted_at"],
                    "disclosed_at": data["disclosed_at"],
                    "vulnerability_information": data["vulnerability_information"],
                    "reporter": data["reporter"].get("username", ""),
                    "program": data["team"]["handle"],
                    "program_url": data["team"]["url"],
                    "weakness": data.get("weakness"),
                    "bounty": data.get("bounty_amount"),
                    "severity": data.get("severity"),
                    "structured_scope": data.get("structured_scope"),
                    "content": [],
                    "public": data.get("public"),
                }

                for summary in data.get("summaries", []):
                    if "content" in summary:
                        report["content"].append(summary["content"])

                yield report
            except Exception as e:
                print(f"ERROR - {report_id}: {e}")

    def write_hacktivity_reports_to_file(self, filename: str):
        """Write all hacktivity reports to a file.

        We will leverage generators to avoid loading all reports into memory and write
        a report to the json file one at a time. To ensure the report is valid json,
        we ensure to capture any errors and ctrl-c signals and close the file properly.
        """

        with open(filename, "w", encoding="utf-8") as f:
            f.write("[\n")

            first_report = True
            try:
                for report in self.list_reports():
                    if first_report:
                        first_report = False
                    else:
                        print(f"{report['id']} - {report['title']}")
                        f.write(",\n")

                    json.dump(report, f, indent=None, separators=(",", ":"))
            except Exception as e:
                print(f"Error: {e}")
            except KeyboardInterrupt:
                pass

            f.write("]\n")


if __name__ == "__main__":
    parser = ArgumentParser(description="HackerOne hacktivity report scraper.")

    parser.add_argument(
        "--cookie",
        help="HackerOne cookie called __Host-session. Login to HackerOne and capture the cookie.",
    )
    parser.add_argument(
        "--filename",
        help="Name of the json file to write the hacktivity reports to (defaults to 'hacktivity.json')",
        default="hacktivity.json",
    )

    args = parser.parse_args()

    if args.cookie is None:
        cookie = input("Enter your HackerOne cookie called '__Host-session': ").strip()
    else:
        cookie = args.cookie

    session = HackerOneSession(cookie=cookie)
    session.write_hacktivity_reports_to_file(args.filename)
