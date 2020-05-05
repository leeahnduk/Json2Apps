from tetpyclient import RestClient
import tetpyclient
import json
import requests.packages.urllib3
import sys
import os
import argparse
import time
import csv
from columnar import columnar
from time import mktime
from datetime import datetime
from argparse import ArgumentParser
from collections import defaultdict
from tqdm import tqdm as progress
import urllib3



CEND = "\33[0m"     #End
CGREEN = "\33[32m"  #Information
CYELLOW = "\33[33m" #Request Input
CRED = "\33[31m"    #Error
URED = "\33[4;31m" 
Cyan = "\33[0;36m"  #Return
BLINK = "\33[5m"
BOLD = "\33[1m"
ITALIC = "\33[3m"
UNDERLINE = "\33[4m"
LBLUE = "\33[1;34m"

# =================================================================================
# feedback: Le Anh Duc - anhdle@cisco.com
# See reason below -- why verify=False param is used
# python3 clean.py --url https://192.168.30.4 --credential dmz_api_credentials.json
# =================================================================================
requests.packages.urllib3.disable_warnings()


parser = argparse.ArgumentParser(description='Tetration Get all sensors')
parser.add_argument('--url', help='Tetration URL', required=True)
parser.add_argument('--credential', help='Path to Tetration json credential file', required=True)
args = parser.parse_args()

# =================================================================================
# Overall
# =================================================================================
def CreateRestClient():
    rc = RestClient(args.url,
                    credentials_file=args.credential, verify=False)
    return rc
def GetApps(rc):
    resp = rc.get('/applications')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve Apps list")
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def ShowApps(apps):
    """
        List all the Apps in Tetration Appliance
        Application ID | App Name | Author | Scope ID | Primary | Enforced
        """
    data_list = []
    headers = ['Number', 'Apps Name', 'Author', 'Scope ID', 'Primary', 'Enforced']
    for i,x in enumerate(apps): data_list.append([i+1,
                    x['name'], x['author'],
                    x['app_scope_id'], x['primary'], x['enforcement_enabled']]) 
    table = columnar(data_list, headers, no_borders=False)
    print(table)


# =================================================================================
# clean
# =================================================================================
def clean(restclient, filter_name):
    errors = []

    # -------------------------------------------------------------------------
    # DELETE THE WORKSPACES
    # Walk through all applications and remove any in a scope that should be
    # deleted. In order to delete an application, we have to turn off enforcing
    # and make it secondary first.

    apps = GetApps(restclient)
    print (CGREEN + "Here is all the application workspaces in your cluster. " + CEND)
    ShowApps(apps)
    choice = input (CYELLOW + "Which apps workspace (number) above you want to delete? " +CEND)
    appName = apps[int(choice)-1]['name']
    for app in apps:
        if appName == app["name"]:
            app_id = app["id"]
            # first we turn off enforcement
            if app["enforcement_enabled"]:
                r = restclient.post('/openapi/v1/applications/' + app_id + '/disable_enforce')
                if r.status_code == 200:
                    print ("[CHANGED] app {} ({}) to not enforcing.".format(app_id, appName))
                else:
                    print ("[ERROR] changing app {} ({}) to not enforcing. Trying again...".format(app_id, appName))
                    time.sleep(1)
                    r = restclient.post('/openapi/v1/applications/' + app_id + '/disable_enforce')
                    if r.status_code == 200:
                        print ("[CHANGED] app {} ({}) to not enforcing.".format(app_id, appName))
                    else:
                        errors.append("[ERROR] Failed again. Details: {} -- {}".format(apps, apps.text))
                        print (apps, apps.text)
            # make the application secondary if it is primary
            if app["primary"]:
                req_payload = {"primary": "false"}
                r = restclient.put('/openapi/v1/applications/' + app_id, json_body=json.dumps(req_payload))
                if r.status_code == 200:
                    print ("[CHANGED] app {} ({}) to secondary.".format(app_id, appName))
                else:
                    # Wait and try again
                    print ("[ERROR] changing app {} ({}) to secondary. Trying again...".format(app_id, appName))
                    time.sleep(1)
                    r = restclient.post('/openapi/v1/applications/' + app_id + '/disable_enforce')
                    if r.status_code == 200:
                        print ("[CHANGED] app {} ({}) to not enforcing.".format(app_id, appName))
                    else:
                        errors.append("[ERROR] Failed again. Details: {} -- {}".format(apps, apps.text))
                        print (apps, apps.text)
            # now delete the app
            r = restclient.delete('/openapi/v1/applications/' + app_id)
            if r.status_code == 200:
                print ("[REMOVED] app {} ({}) successfully.".format(app_id, appName))
            else:
                # Wait and try again
                print ("[ERROR] deleting {} ({}). Trying again...".format(app_id, appName))
                time.sleep(1)
                r = restclient.delete('/openapi/v1/applications/' + app_id)
                if r.status_code == 200:
                    print ("[REMOVED] app {} ({}) successfully.".format(app_id, appName))
                else:
                    errors.append("[ERROR] Failed again. Details: {} -- {}".format(apps, apps.text))
                    print (apps, apps.text)

    # -------------------------------------------------------------------------
    # DETERMINE ALL FILTERS ASSOCIATED WITH THIS VRF_ID
    # Inventory filters have a query that the user enters but there is also a
    # query for the vrf_id to match. So we simply walk through all filters and
    # look for that query to match this vrf_id... if there is a match then
    # mark the filter as a target for deletion.  Before deleting filters,
    # we need to delete the agent config intents

    filtersToBeDeleted = []

    resp = restclient.get('/openapi/v1/filters/inventories')
    if resp.status_code == 200:
        resp_data = resp.json()
    else:
        print ("[ERROR] reading filters to determine which ones should be deleted.")
        errors.append("[ERROR] reading filters to determine which ones should be deleted.")
        print (resp, resp.text)
        resp_data = {}
    for filt in resp_data:
        if filter_name in filt["name"]:
            inventory_filter_id = filt["id"]
            filterName = filt["name"]
            filtersToBeDeleted.append({'id': inventory_filter_id, 'name': filterName})
          
    # -------------------------------------------------------------------------
    # DELETE THE FILTERS

    while len(filtersToBeDeleted):
        filterId = filtersToBeDeleted.pop()
        r = restclient.delete('/openapi/v1/filters/inventories/' + filterId['id'])
        if r.status_code == 200:
            print ("[REMOVED] inventory filter {} named '{}'.".format(filterId['id'], filterId['name']))
        else:
            print ("[ERROR] removing inventory filter {} named '{}'.".format(filterId['id'], filterId['name']))
            errors.append("[ERROR] removing inventory filter {} named '{}'.".format(filterId['id'], filterId['name']))
            print (r, r.text)


def main():
    # clean all objects created by json2apps
    rc= CreateRestClient()
    clean(rc, "sock-shop")

if __name__ == "__main__":
    main()