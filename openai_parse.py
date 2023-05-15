import os
import openai
import json
import re

openai.api_key = os.getenv("OPENAI_API_KEY")

xss_prompt = """
Hello SecParseGPT, I have a bug bounty report that I need you to parse for cross-site scripting (XSS) vulnerabilities. The report may contain incomplete or markdown-formatted text, and the vulnerable parameters could appear in various parts of the report, such as URLs, descriptions, or HTTP requests.

Using natural language processing techniques such as named entity recognition (NER) and part-of-speech (POS) tagging, please extract the names of all parameters that are vulnerable to XSS attacks. The output should only list the names of the parameters, and not include any impact, descriptions, or explanations.

Please note that the response should be less than 25 tokens. Thank you for your assistance. The next message is the bug bounty report.
"""

ssti_prompt = """
Hello SecParseGPT, I have a bug bounty report that I need you to parse for side template injection (SSTI) vulnerabilities. The report may contain incomplete or markdown-formatted text, and the vulnerable parameters could appear in various parts of the report, such as URLs, descriptions, or HTTP requests.

Using natural language processing techniques such as named entity recognition (NER) and part-of-speech (POS) tagging, please extract the names of all parameters that are vulnerable to XSS attacks. The output should only list the names of the parameters, and not include any impact, descriptions, or explanations.

Please note that the response should be less than 25 tokens. Thank you for your assistance. The next message is the bug bounty report.
"""

ssrf_prompt = """
Hello SecParseGPT, I have a bug bounty report that I need you to parse for server side request forgery (SSRF) vulnerabilities. The report may contain incomplete or markdown-formatted text, and the vulnerable parameters could appear in various parts of the report, such as URLs, descriptions, or HTTP requests.

Using natural language processing techniques such as named entity recognition (NER) and part-of-speech (POS) tagging, please extract the names of all parameters that are vulnerable to XSS attacks. The output should only list the names of the parameters, and not include any impact, descriptions, or explanations.

Please note that the response should be less than 25 tokens. Thank you for your assistance. The next message is the bug bounty report.
"""

sqli_prompt = """
Hello SecParseGPT, I have a bug bounty report that I need you to parse for server SQL Injection (SQli) vulnerabilities. The report may contain incomplete or markdown-formatted text, and the vulnerable parameters could appear in various parts of the report, such as URLs, descriptions, or HTTP requests.

Using natural language processing techniques such as named entity recognition (NER) and part-of-speech (POS) tagging, please extract the names of all parameters that are vulnerable to XSS attacks. The output should only list the names of the parameters, and not include any impact, descriptions, or explanations.

Please note that the response should be less than 25 tokens. Thank you for your assistance. The next message is the bug bounty report.
"""

file_incl_prompt = """
Hello SecParseGPT, I have a bug bounty report that I need you to parse for path transversal vulnerabilities. The report may contain incomplete or markdown-formatted text, and the vulnerable parameters could appear in various parts of the report, such as URLs, descriptions, or HTTP requests.

Using natural language processing techniques such as named entity recognition (NER) and part-of-speech (POS) tagging, please extract the names of all parameters that are vulnerable to XSS attacks. The output should only list the names of the parameters, and not include any impact, descriptions, or explanations.

Please note that the response should be less than 25 tokens. Thank you for your assistance. The next message is the bug bounty report.
"""

idor_prompt = """
Hello SecParseGPT, I have a bug bounty report that I need you to parse for insecure direct object reference (IDOR) vulnerabilities. The report may contain incomplete or markdown-formatted text, and the vulnerable parameters could appear in various parts of the report, such as URLs, descriptions, or HTTP requests.

Using natural language processing techniques such as named entity recognition (NER) and part-of-speech (POS) tagging, please extract the names of all parameters that are vulnerable to XSS attacks. The output should only list the names of the parameters, and not include any impact, descriptions, or explanations.

Please note that the response should be less than 25 tokens. Thank you for your assistance. The next message is the bug bounty report.
"""

redirect_prompt = """
Hello SecParseGPT, I have a bug bounty report that I need you to parse for Open Redirect vulnerabilities. The report may contain incomplete or markdown-formatted text, and the vulnerable parameters could appear in various parts of the report, such as URLs, descriptions, or HTTP requests.

Using natural language processing techniques such as named entity recognition (NER) and part-of-speech (POS) tagging, please extract the names of all parameters that are vulnerable to XSS attacks. The output should only list the names of the parameters, and not include any impact, descriptions, or explanations.

Please note that the response should be less than 25 tokens. Thank you for your assistance. The next message is the bug bounty report.
"""

class Parser:
    def __init__(self):
        self.messages = []
    
    def setForXss(self):
        self.messages.append({"role": "system", "content": xss_prompt})
    
    def setForSsti(self):
        self.messages.append({"role": "system", "content": ssti_prompt})

    def setForSsrf(self):
        self.messages.append({"role": "system", "content": ssrf_prompt})

    def setForSqli(self):
        self.messages.append({"role": "system", "content": sqli_prompt})

    def setForFileIncl(self):
        self.messages.append({"role": "system", "content": file_incl_prompt})

    def setForIdor(self):
        self.messages.append({"role": "system", "content": idor_prompt})

    def setForRedirect(self):
        self.messages.append({"role": "system", "content": redirect_prompt})

    def get_params(self, message):
        try: 
            self.messages.append({"role": "user", "content": message})
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=self.messages,
                max_tokens=50,
                n=1,
                stop=None,
                temperature=0.5,
            )

            self.messages.append({"role": "assistant", "content": response["choices"][0]["message"].content})
            return response["choices"][0]["message"]['content']
        except openai.error.InvalidRequestError:
            return "ERROR"



if __name__ == "__main__":
    f = open('json_files/vulns.json')
    data = json.load(f)
    # output lists
    xss_output_list = []
    ssti_output_list = []
    ssrf_output_list = []
    sqli_output_list = []
    file_incl_output_list = []
    idor_output_list = []
    redirect_output_list = []

    # parsers
    xssParser = Parser()
    xssParser.setForXss()

    sstiParser = Parser()
    sstiParser.setForSsti()

    ssrfParser = Parser()
    ssrfParser.setForSsrf()

    sqliParser = Parser()
    sqliParser.setForSqli()

    file_inclParser = Parser()
    file_inclParser.setForFileIncl()

    idorParser = Parser()
    idorParser.setForIdor()

    redirectParser = Parser()
    redirectParser.setForRedirect()

    for report in data[0:250]:
        # Find XSS Vulnerable Parameters
        if "name" in report['weakness'].keys():
            if "xss" in report['weakness']['name'].lower():
                xss_output_list.append(xssParser.get_params(report['vulnerability_information']))
        else:
            if "xss" in report['title'].lower() or "cross site scripting" in report['title'].lower():
                xss_output_list.append(xssParser.get_params(report['vulnerability_information']))
        
        # Find SSTI Vulnerable Parameters
        if "ssti" in report['title'].lower() or "server side template injection" in report['title'].lower():
            ssti_output_list.append(sstiParser.get_params(report['vulnerability_information']))
        
        # Find SSRF Vulnerable Parameters
        if "name" in report['weakness'].keys():
            if "ssrf" in report['weakness']['name'].lower():
                ssrf_output_list.append(ssrfParser.get_params(report['vulnerability_information']))
        else:
            if "ssrf" in report['title'].lower() or "server side request forgery" in report['title'].lower():
                ssrf_output_list.append(ssrfParser.get_params(report['vulnerability_information']))

        # Find SQLi Vulnerable Parameters
        if "name" in report['weakness'].keys():
            if "sql injection" in report['weakness']['name'].lower():
                sqli_output_list.append(sqliParser.get_params(report['vulnerability_information']))
        else:
            if "sqli" in report['title'].lower() or "sql injection" in report['title'].lower():
                sqli_output_list.append(sqliParser.get_params(report['vulnerability_information']))
        
        # Find file incl. Vulnerable Parameters
        if "name" in report['weakness'].keys():
            if "path traversal" in report['weakness']['name'].lower():
                file_incl_output_list.append(file_inclParser.get_params(report['vulnerability_information']))
        else:
            if "lfi" in report['title'].lower() or "path traversal" in report['title'].lower():
                file_incl_output_list.append(file_inclParser.get_params(report['vulnerability_information']))
        
        # Find IDOR Vulnerable Parameters
        if "name" in report['weakness'].keys():
            if "idor" in report['weakness']['name'].lower():
                idor_output_list.append(idorParser.get_params(report['vulnerability_information']))
        else:
            if "idor" in report['title'].lower():
                idor_output_list.append(idorParser.get_params(report['vulnerability_information']))
        
        # Find Open Redirect Vulnerable Parameters
        if "name" in report['weakness'].keys():
            if "open redirect" in report['weakness']['name'].lower():
                redirect_output_list.append(redirectParser.get_params(report['vulnerability_information']))
        else:
            if "open redirect" in report['title'].lower():
                redirect_output_list.append(redirectParser.get_params(report['vulnerability_information']))
    
    print("=======XSS============")
    print(xss_output_list)

    print("=======SSTI============")
    print(ssti_output_list)

    print("=======SSRF============")
    print(ssrf_output_list)

    print("=======SQLi============")
    print(sqli_output_list)

    print("=======IDOR============")
    print(idor_output_list)

    print("=======FileIncl============")
    print(file_incl_output_list)

    print("=======OpenRedirect============")
    print(redirect_output_list)
