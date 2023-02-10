import json
import requests

def get_all_rules(auth):
    endpoint_uri = 'https://security.microsoft.com/apiproxy/mtp/huntingService/queries/?type=scheduled'
    headers = {"x-xsrf-token": auth['session_xsrf_token']}
    cookies = {"sccauth": auth['session_sccauth']}
    response = requests.get(endpoint_uri, headers = headers,cookies = cookies)
    if response: return json.loads(response.text)
    else: raise Exception("Unable to get rules from master tenant, did the session time out?")

def get_rule_querytext(id, auth):
    endpoint_uri = f'https://security.microsoft.com/apiproxy/mtp/huntingService/queries/{id}'
    headers = {"x-xsrf-token": auth['session_xsrf_token']}
    cookies = {"sccauth": auth['session_sccauth']}
    response = requests.get(endpoint_uri, headers = headers,cookies = cookies)
    response = json.loads(response.text)
    return response['QueryText']

def get_rule_details(id, auth):
    endpoint_uri = f'https://security.microsoft.com/apiproxy/mtp/huntingService/rules/byquery/{id}'
    headers = {"x-xsrf-token": auth['session_xsrf_token']}
    cookies = {"sccauth": auth['session_sccauth']}
    response = requests.get(endpoint_uri, headers = headers,cookies = cookies)
    response = json.loads(response.text)
    return response

def get_rule_details(id, auth):
    endpoint_uri = f'https://security.microsoft.com/apiproxy/mtp/huntingService/rules/byquery/{id}'
    headers = {"x-xsrf-token": auth['session_xsrf_token']}
    cookies = {"sccauth": auth['session_sccauth']}
    response = requests.get(endpoint_uri, headers = headers,cookies = cookies)
    response = json.loads(response.text)
    return response

def push_rule(rule, auth):
    endpoint_uri = 'https://security.microsoft.com/apiproxy/mtp/huntingService/rules/'
    headers = {"x-xsrf-token": auth['session_xsrf_token'], "method": "POST"}
    cookies = {"sccauth": auth['session_sccauth']}
    response = requests.post(endpoint_uri, json = rule.__dict__, headers = headers,cookies = cookies)
    return response

class Rule:
    def __init__(self, rule_id, auth):
        rule_details = get_rule_details(rule_id, auth)
        self.Name = rule_details['Name']
        self.Title = rule_details['Title']
        self.Description = rule_details['Description']
        self.IntervalHours = rule_details['IntervalHours']
        self.Severity = rule_details['Severity']
        self.Category = rule_details['Category']
        self.MitreTechniques = rule_details['MitreTechniques']
        self.RecommendedAction = rule_details['RecommendedAction']
        self.RbacGroupIds = rule_details['RbacGroupIds']
        self.IsEnabled = 0
        self.QueryText = get_rule_querytext(rule['Id'], auth)
        self.AlertDescription = rule_details['Description']
        self.AlertSeverity = rule_details['Severity']
        self.AlertCategory = rule_details['Category']
        self.AlertRecommendedAction = rule_details['RecommendedAction']
        self.CustomActions = rule_details['CustomActions']
        self.ImpactedEntities = rule_details['ImpactedEntities']

with open("config.json", "r") as fh:
    auth = json.loads(fh.read())
    auth['master']['session_xsrf_token'] = auth['master']['session_xsrf_token'].replace('%3A', ":")
    all_rules = get_all_rules(auth=auth['master'])

    for rule in all_rules:
        print(f"[+] Transferring rule '{rule['Name']} ({rule['Id']})'")
        ruleObj = Rule(rule['Id'], auth=auth['master'])

        for slave in auth['slaves']:
            auth['slaves'][slave]['session_xsrf_token'] = auth['slaves'][slave]['session_xsrf_token'].replace('%3A', ":")
            response = push_rule(ruleObj, auth['slaves'][slave])
            if not response.status_code == 201:
                print(f"[!] Something went wrong with slave '{slave}' and rule '{rule['Name']}! (Reponse code: {response.status_code} ({response.reason}))\n")
            else:
                print(f"[+] Success with slave '{slave}' and rule '{rule['Name']}!\n")
