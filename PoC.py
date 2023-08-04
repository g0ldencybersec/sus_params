import openai
import os
import json
import tiktoken
import time

openai.api_key = os.getenv("OPENAI_API_KEY")
model_id = "gpt-4"

def chatgpt_conversation(conversation_log):
    response = openai.ChatCompletion.create(
        model=model_id,
        messages=conversation_log
    )

    conversation_log.append({
        'role': response.choices[0].message.role, 
        'content': response.choices[0].message.content.strip()
    })
    return conversation_log

def handleXSS(vuln, conversation):
    if vuln['vulnerability_information'] != "" and num_tokens_from_string(vuln['vulnerability_information'], "gpt-4") < 8000:
        num_tokens_from_string(vuln['vulnerability_information'], "gpt-4")
        prompt="""
        Vulnerability report: {}

        Please identify the name(s) of the vulnerable parameter(s) from the above cross site scripting report. If none exist or you can't locate any just say none.
        """.format(vuln['vulnerability_information'].encode('utf-8').decode('utf-8'))
        conversation.append({'role': 'user', 'content': prompt})
        conversation = chatgpt_conversation(conversation)

def handleSSRF(vuln, conversation):
    if vuln['vulnerability_information'] != "" and num_tokens_from_string(vuln['vulnerability_information'], "gpt-4") < 8000:
        prompt="""
        Vulnerability report: {}

        Please identify the name(s) of the vulnerable parameter(s) from the above Server Side Request Forgery report. If none exist or you can't locate any just say none.
        """.format(vuln['vulnerability_information'].encode('utf-8').decode('utf-8'))
        conversation.append({'role': 'user', 'content': prompt})
        conversation = chatgpt_conversation(conversation)


def handleSQLI(vuln, conversation):
    if vuln['vulnerability_information'] != "" and num_tokens_from_string(vuln['vulnerability_information'], "gpt-4") < 8000:
        prompt="""
        Vulnerability report: {}

        Please identify the name(s) of the vulnerable parameter(s) from the above SQL injection report. If none exist or you can't locate any just say none.
        """.format(vuln['vulnerability_information'].encode('utf-8').decode('utf-8'))
        conversation.append({'role': 'user', 'content': prompt})
        conversation = chatgpt_conversation(conversation)

def handleFileInc(vuln, conversation):
    if vuln['vulnerability_information'] != "" and num_tokens_from_string(vuln['vulnerability_information'], "gpt-4") < 8000:
        prompt="""
        Vulnerability report: {}

        Please identify the name(s) of the vulnerable parameter(s) from the above file vuln report. If none exist or you can't locate any just say none.
        """.format(vuln['vulnerability_information'].encode('utf-8').decode('utf-8'))
        conversation.append({'role': 'user', 'content': prompt})
        conversation = chatgpt_conversation(conversation)

def handleSSTI(vuln, conversation):
    if vuln['vulnerability_information'] != "" and num_tokens_from_string(vuln['vulnerability_information'], "gpt-4") < 8000:
        prompt="""
        Vulnerability report: {}

        Please identify the name(s) of the vulnerable parameter(s) from the above Server Side Template Injection report. If none exist or you can't locate any just say none.
        """.format(vuln['vulnerability_information'].encode('utf-8').decode('utf-8'))
        conversation.append({'role': 'user', 'content': prompt})
        conversation = chatgpt_conversation(conversation)


def handleIDOR(vuln, conversation):
    if vuln['vulnerability_information'] != "" and num_tokens_from_string(vuln['vulnerability_information'], "gpt-4") < 8000:
        prompt="""
        Vulnerability report: {}

        Please identify the name(s) of the vulnerable parameter(s) from the above idor report. If none exist or you can't locate any just say none.
        """.format(vuln['vulnerability_information'].encode('utf-8').decode('utf-8'))
        conversation.append({'role': 'user', 'content': prompt})
        conversation = chatgpt_conversation(conversation)


def handleOpenRedirect(vuln, conversation):
    if vuln['vulnerability_information'] != "" and num_tokens_from_string(vuln['vulnerability_information'], "gpt-4") < 8000:
        prompt="""
        Vulnerability report: {}

        Please identify the name(s) of the vulnerable parameter(s) from the above Open Redirect report. If none exist or you can't locate any just say none.
        """.format(vuln['vulnerability_information'].encode('utf-8').decode('utf-8'))
        conversation.append({'role': 'user', 'content': prompt})
        conversation = chatgpt_conversation(conversation)

def grabConvo(vuln_type, conversation):
    if len(conversation) > 0:
        file = open(f"test/{vuln_type}-file.txt", "a")
        for line in conversation:
            if line['role'] == "assistant":
                file.write(line['content'] + "\n\n")
        file.close()
    else:
        print(f"{vuln_type} List is empty")

def num_tokens_from_string(string: str, encoding_name: str):
    encoding = tiktoken.encoding_for_model(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens



if __name__ == "__main__":
    # Conversations
    xss_conversation = []
    fileinc_conversation = []
    idor_conversation = []
    redirect_conversation =[]
    sqli_conversation = []
    ssrf_conversation = []
    ssti_conversation = []

    # Parse huge vuln.json file
    with open('json_files/vulns.json') as user_file:
        file_contents = user_file.read()

    parsed_json = json.loads(file_contents)
    count = 784
    total = len(parsed_json)
    retryFlag = False
    while count < total:
        vuln = parsed_json[count]
        try:
            print(f"Parsing vuln #{count} of {total}")
            if "name" in vuln["weakness"].keys():
                if "xss" in vuln['weakness']['name'].lower():
                    handleXSS(vuln, xss_conversation)
                    grabConvo("xss", xss_conversation)
                    xss_conversation.clear()
                if "ssrf" in vuln['weakness']['name'].lower():
                    handleSSRF(vuln, ssrf_conversation)
                    grabConvo("ssrf", ssrf_conversation)
                    ssrf_conversation.clear()
                if "sql injection" in vuln['weakness']['name'].lower():
                    handleSQLI(vuln, sqli_conversation)
                    grabConvo("sqli", sqli_conversation)
                    sqli_conversation.clear()
                if "path traversal" in vuln['weakness']['name'].lower():
                    handleFileInc(vuln, fileinc_conversation)
                    grabConvo("fileinc", fileinc_conversation)
                    fileinc_conversation.clear()
                if "idor" in vuln['weakness']['name'].lower():
                    handleIDOR(vuln, idor_conversation)
                    grabConvo("idor", idor_conversation)
                    idor_conversation.clear()
                if "open redirect" in vuln['weakness']['name'].lower():
                    handleOpenRedirect(vuln, redirect_conversation)
                    grabConvo("redirect", redirect_conversation)
                    redirect_conversation.clear() 
            else:
                if "xss" in vuln['title'].lower() or "cross site scripting" in vuln['title'].lower():
                    handleXSS(vuln, xss_conversation)
                    grabConvo("xss", xss_conversation)
                    xss_conversation.clear()
                if "ssti" in vuln['title'].lower() or "server side template injection" in vuln['title'].lower():
                    handleSSTI(vuln, ssti_conversation)
                    grabConvo("ssti", ssti_conversation)
                    ssti_conversation.clear()
                if "ssrf" in vuln['title'].lower() or "server side request forgery" in vuln['title'].lower():
                    handleSSRF(vuln, ssrf_conversation)
                    grabConvo("ssrf", ssrf_conversation)
                    ssrf_conversation.clear()
                if "sqli" in vuln['title'].lower() or "sql injection" in vuln['title'].lower():
                    handleSQLI(vuln, sqli_conversation)
                    grabConvo("sqli", sqli_conversation)
                    sqli_conversation.clear()
                if "lfi" in vuln['title'].lower() or "path traversal" in vuln['title'].lower():
                    handleFileInc(vuln, fileinc_conversation)
                    grabConvo("fileinc", fileinc_conversation)
                    fileinc_conversation.clear()
                if "idor" in vuln['title'].lower():
                    handleIDOR(vuln, idor_conversation)
                    grabConvo("idor", idor_conversation)
                    idor_conversation.clear()
                if "open redirect" in vuln['title'].lower():
                    handleOpenRedirect(vuln, redirect_conversation)
                    grabConvo("redirect", redirect_conversation)
                    redirect_conversation.clear()
            retryFlag = False
            count = count + 1
            time.sleep(1)
        except openai.error.RateLimitError as e:
            retry_time = e.retry_after if hasattr(e, 'retry_after') else 60
            print(f"Rate limit exceeded. Retrying in {retry_time} seconds...")
            time.sleep(retry_time)
            if retryFlag:
                print("Still timed out after retry for:", e)
                break
            else:
                retryFlag = True
        except openai.error.ServiceUnavailableError as e:
            retry_time = 15  # Adjust the retry time as needed
            print(f"Service is unavailable. Retrying in {retry_time} seconds...")
            time.sleep(retry_time)
            if retryFlag:
                print("Still timed out after retry for:", e)
                break
            else:
                retryFlag = True
        except Exception as e:
            print("An unexpected error occurred I didnt catch:", e)
            break
