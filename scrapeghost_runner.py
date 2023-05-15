from scrapeghost import SchemaScraper, errors
import json
import openai

################################
#                              #
#           PROMPTS            #
#                              #
################################
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

################################
#                              #
#           FUNCTIONS          #
#                              #
################################

def get_params(vuln_info, prompt_type):
  if vuln_info == "":
    return None
  else:
    try:
      match prompt_type:
        case "xss":
          scrape_legislators = SchemaScraper(
          schema={
              "vulnerability_name": "string",
              "vulnerable_parameters": ["str"],
          },
          extra_instructions=[xss_prompt]
          ) 
          resp = scrape_legislators(vuln_info)
          return resp.data
        case "ssti":
          scrape_legislators = SchemaScraper(
          schema={
              "vulnerability_name": "string",
              "vulnerable_parameters": ["str"],
          },
          extra_instructions=[ssti_prompt]
          )
          resp = scrape_legislators(vuln_info)
          return resp.data
        case "ssrf":
          scrape_legislators = SchemaScraper(
          schema={
              "vulnerability_name": "string",
              "vulnerable_parameters": ["str"],
          },
          extra_instructions=[ssrf_prompt]
          ) 
          resp = scrape_legislators(vuln_info)
          return resp.data
        case "sqli":
          scrape_legislators = SchemaScraper(
          schema={
              "vulnerability_name": "string",
              "vulnerable_parameters": ["str"],
          },
          extra_instructions=[sqli_prompt]
          ) 
          resp = scrape_legislators(vuln_info)
          return resp.data
        case "filei":
          scrape_legislators = SchemaScraper(
          schema={
              "vulnerability_name": "string",
              "vulnerable_parameters": ["str"],
          },
          extra_instructions=[file_incl_prompt]
          ) 
          resp = scrape_legislators(vuln_info)
          return resp.data
        case "idor":
          scrape_legislators = SchemaScraper(
          schema={
              "vulnerability_name": "string",
              "vulnerable_parameters": ["str"],
          },
          extra_instructions=[idor_prompt]
          )
          resp = scrape_legislators(vuln_info)
          return resp.data
        case "redirect":
          scrape_legislators = SchemaScraper(
          schema={
              "vulnerability_name": "string",
              "vulnerable_parameters": ["str"],
          },
          extra_instructions=[redirect_prompt]
          ) 
          resp = scrape_legislators(vuln_info)
          return resp.data
        case _:
          return None
    # Malformed response
    except errors.InvalidJSON:
      return None
    # Normally this one is due to the report being too many tokens... GPT-4 would fix this.
    except openai.error.InvalidRequestError:
      return None
    except errors.TooManyTokens:
      return None
    except:
      return None
    



if __name__ == "__main__":
  f = open('json_files/vulns.json')
  data = json.load(f)

  output = {"xss": [], "ssti": [], "ssrf": [], "sqli": [], "file_incl": [], "idor": [], "redirect": [], "errors": 0}
  for report in data:
    # Find XSS Vulnerable Parameters
    if "name" in report['weakness'].keys():
      if "xss" in report['weakness']['name'].lower():
        results = get_params(report['vulnerability_information'], "xss")
        if results != None:
          output['xss'].append(results)
    else:
      if "xss" in report['title'].lower() or "cross site scripting" in report['title'].lower():
        results = get_params(report['vulnerability_information'], "xss")
        if results != None:
          output['xss'].append(results)
    # Find SSTI Vulnerable Parameters
    if "ssti" in report['title'].lower() or "server side template injection" in report['title'].lower():
      results = get_params(report['vulnerability_information'], "ssti")
      if results != None:
        output['ssti'].append(results)
    
    # Find SSRF Vulnerable Parameters
    if "name" in report['weakness'].keys():
      if "ssrf" in report['weakness']['name'].lower():
        results = get_params(report['vulnerability_information'], "ssrf")
        if results != None:
          output['ssrf'].append(results)
    else:
      if "ssrf" in report['title'].lower() or "server side request forgery" in report['title'].lower():
        results = get_params(report['vulnerability_information'], "ssrf")
        if results != None:
          output['ssrf'].append(results)

    # Find SQLi Vulnerable Parameters
    if "name" in report['weakness'].keys():
      if "sql injection" in report['weakness']['name'].lower():
        results = get_params(report['vulnerability_information'], "sqli")
        if results != None:
          output['sqli'].append(results)
    else:
      if "sqli" in report['title'].lower() or "sql injection" in report['title'].lower():
        results = get_params(report['vulnerability_information'], "sqli")
        if results != None:
          output['sqli'].append(results)    
    
    # Find file incl. Vulnerable Parameters
    if "name" in report['weakness'].keys():
      if "path traversal" in report['weakness']['name'].lower():
        results = get_params(report['vulnerability_information'], "filei")
        if results != None:
          output['file_incl'].append(results)
    else:
      if "lfi" in report['title'].lower() or "path traversal" in report['title'].lower():
        results = get_params(report['vulnerability_information'], "filei")
        if results != None:
          output['file_incl'].append(results)
    
    # Find IDOR Vulnerable Parameters
    if "name" in report['weakness'].keys():
      if "idor" in report['weakness']['name'].lower():
        results = get_params(report['vulnerability_information'], "idor")
        if results != None:
          output['idor'].append(results)
    else:
      if "idor" in report['title'].lower():
        results = get_params(report['vulnerability_information'], "idor")
        if results != None:
          output['idor'].append(results)
    
    # Find Open Redirect Vulnerable Parameters
    if "name" in report['weakness'].keys():
      if "open redirect" in report['weakness']['name'].lower():
        results = get_params(report['vulnerability_information'], "redirect")
        if results != None:
          output['redirect'].append(results)
    else:
      if "open redirect" in report['title'].lower():
        results = get_params(report['vulnerability_information'], "redirect")
        if results != None:
          output['redirect'].append(results)

  with open('json_files/OpenAI_parsed.json', 'w') as fout:
    json.dump(output, fout, indent=4)
    fout.close()