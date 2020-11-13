import tetpyclient
import json
import requests.packages.urllib3
import sys
import os
import argparse
import time
import csv

from argparse import ArgumentParser
from collections import defaultdict
from datetime import datetime
from builtins import input
from columnar import columnar

from tetpyclient import RestClient
from tqdm import tqdm as progress
import urllib3

CEND = "\33[0m"     #End
CGREEN = "\33[32m"  #Information
CYELLOW = "\33[33m" #Request Input
CRED = "\33[31m"    #Error
URED = "\33[4;31m" 
Cyan = "\33[0;36m"  #Return

# =================================================================================
# See reason below -- why verify=False param is used
# python3 json2apps.py --url https://192.168.30.4 --credential dmz_api_credentials.json --policies sockshop.json
# feedback: Le Anh Duc - anhdle@cisco.com
# =================================================================================
requests.packages.urllib3.disable_warnings()


parser = argparse.ArgumentParser(description='Tetration Create Policy under Apps')
parser.add_argument('--url', help='Tetration URL', required=True)
parser.add_argument('--credential', help='Path to Tetration json credential file', required=True)
parser.add_argument('--policies', default=None, help='Path to Policies Configuration file')
args = parser.parse_args()


def CreateRestClient():
    """create REST API connection to Tetration cluster
    Returns:
        REST Client
    """
    rc = RestClient(args.url,
                    credentials_file=args.credential, verify=False)
    return rc

def GetApps(rc):
    resp = rc.get('/applications')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve Apps list" + CEND)
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def GetAppsId(Apps, name):
    try:
        for app in Apps: 
            if name == app["name"]: return app["id"]
    except:
        print(URED + "Failed to retrieve App ID "+ CEND)

def ShowApps(Apps):
    AppsList = []
    headers = ['Number', 'App Name', 'Author', 'App ID', 'Primary?']
    for i,app in enumerate(Apps): AppsList.append([i+1,app["name"] , app['author'], app["id"], app['primary']])
    table = columnar(AppsList, headers, no_borders=False)
    print(table)

def GetApplicationScopes(rc):
    resp = rc.get('/app_scopes')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve app scopes")
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def GetAppScopeId(scopes,name):
    try:
        return [scope["id"] for scope in scopes if scope["name"] == name][0]
    except:
        print(URED + "App Scope {name} not found".format(name=name))

def ShowScopes(scopes):
    ScopesList = []
    headers = ['Number', 'Scope Name', 'Scope ID', 'VRF ID']
    for i,scope in enumerate(scopes): ScopesList.append([i+1,scope["name"] , scope["id"], scope['vrf_id']])
    table = columnar(ScopesList, headers, no_borders=False)
    print(table)

def GetPolicies(rc, app_id):
    
    resp = rc.get('/applications/' + app_id + '/policies')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve Policies list")
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def getDefaultDetail(rc, id):
    resp = rc.get('/applications/'+ id + '/default_policies')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve Default Policies from your Apps"+ CEND)
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json() 

def getAbsoluteDetail(rc, id):
    resp = rc.get('/applications/'+ id + '/absolute_policies')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve Absolute Policies from your Apps"+ CEND)
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json() 

def getCatchAllDetail(rc, id):
    resp = rc.get('/applications/'+ id + '/catch_all')
    if resp.status_code != 200:
        print(URED + "Failed to retrieve catch_all Policy from your Apps"+ CEND)
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def selectTetApps(apps):
    # Return App IDa for one or many Tetration Apps that we choose
    print (Cyan + "\nHere are all Application workspaces in your cluster: " + CEND)
    ShowApps(apps)
    choice = input('\nSelect which Tetration Apps (Number, Number) above you want to download polices: ')

    choice = choice.split(',')
    appIDs = []
    for app in choice:
        if '-' in app:
            for app in range(int(app.split('-')[0])-1,int(app.split('-')[1])):
                appIDs.append(resp.json()[int(app)-1]['id'])
        else:
            appIDs.append(apps[int(app)-1]['id'])
    return appIDs

def downloadPolicies(rc,appIDs):
    # Download Policies JSON files from Apps workspace
    apps = []
    for appID in appIDs:
        print('Downloading app details for '+appID + "into json file")
        apps.append(rc.get('/openapi/v1/applications/%s/details'%appID).json())
        #json_object = json.load(apps)
    for app in apps:
        with open('./'+app['name'].replace('/','-')+'.json', "w") as config_file:
            json.dump(apps, config_file, indent=4)
            print(app['name'].replace('/','-')+".json created")


def GetAppVersions(rc, appid):
    resp = rc.get('/applications/' + appid + '/versions')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve list of versions for your app" + CEND)
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def GetLatestVersion(app_versions):
    try:
        for vers in app_versions: 
            if "v" in vers["version"]: return vers["version"]
    except:
        print(URED + "Failed to retrieve latest app version"+ CEND)

def getAppDetail(rc, id):
    resp = rc.get('/applications/'+ id)

    if resp.status_code != 200:
        print(URED + "Failed to retrieve App detail"+ CEND)
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json() 

def GetPolicies(rc, app_id):
    
    resp = rc.get('/applications/' + app_id + '/policies')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve Policies list"+ CEND)
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def GetInventoriesId(inventories, name):
    try:
        for inv in inventories:
            if name == inv["name"]:
                print (Cyan + "\nHere is your Inventory ID: " + inv["id"] + Cend)
                return inv["id"]
            else: continue
    except:
        print(URED + "Inventory {name} not found".format(name=name)) 

def GetInventoriesNamewithID(inventories):
    inventoriesList = []
    try:
        for inv in inventories: 
            inventoriesList.append([inv["name"] , inv["id"]])
        return inventoriesList
    except:
        print(URED + "Failed to retrieve inventories name with ID list"+ CEND) 


def GetInventories(rc):
    resp = rc.get('/filters/inventories')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve inventories list"+ CEND)
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def filterToString(invfilter):
    if 'filters' in invfilter.keys():
        query=[]
        for x in invfilter['filters']:
            if 'filters' in x.keys():
                query.append(filterToString(x))
            elif 'filter' in x.keys():
                query.append(x['type'] + filterToString(x['filter']))
            else:
                query.append(x['field'].replace('user_','*')+ ' '+ x['type'] + ' '+ str(x['value']))
        operator = ' '+invfilter['type']+' '
        return '('+operator.join(query)+')'
    else:
        return invfilter['field']+ ' '+ invfilter['type'] + ' '+ str(invfilter['value'])

def GetInventoriesId(inventories, name):
    try:
        for inv in inventories:
            if name == inv["name"]:
                print (Cyan + "\nHere is your Inventory ID: " + inv["id"])
                return inv["id"]
            else: continue
    except:
        print(URED + "Inventory {name} not found".format(name=name))


def GetAppScopeName(scopes,id):
    try:
        return [scope["name"] for scope in scopes if scope["id"] == id][0]
    except:
        print("App Scope {id} not found".format(name=name)) 

def ShowApplicationScopes(scopes):
    """
        List all the Scopes in Tetration Appliance
        Scope ID | Name | Policy Priority | Query | VRF ID | Parent Scope ID | Root Scope ID | Created At | Updated At
        """
    headers = ['Scope ID', 'Name', 'Policy Priority', 'Query', 'VRF ID', 'Parent Scope ID', 'Root Scope ID', 'Created At', 'Updated At']
    data_list = []
    for x in scopes: data_list. append([x['id'],
                    x['name'],
                    x['policy_priority'],
                    x['short_query'],
                    x['vrf_id'],
                    x['parent_app_scope_id'],
                    x['root_app_scope_id'],
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(x['created_at'])),
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(x['updated_at']))])
    table = columnar(data_list, headers, no_borders=False)
    print(table)

def GetVRFs(rc):
    # Get all VRFs in the cluster
    resp = rc.get('/vrfs')

    if resp.status_code != 200:
        print("Failed to retrieve app scopes")
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def ShowVRFs(vrfs):
    """
        List all the Apps in Tetration Appliance
        VRF ID | Created At | Updated At | Name | Tenant name | Root Scope ID
        """
    data_list = []
    headers = ['VRF ID', 'Created At', 'Updated At', 'Name', 'Tenant Name', 'Root Scope ID']
    for x in vrfs: 
        data_list.append([x['id'], time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(x['created_at'])), time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(x['updated_at'])), x['name'], x['tenant_name'], x['root_app_scope_id']]) 
    table = columnar(data_list, headers, no_borders=False)
    print(table)

def GetRootScope(vrfs):
    #return list of Root Scopes and its' names
    rootScopes = []
    headers = ['Root Scope Name', 'VRF ID']
    for vrf in vrfs:
        rootScopes.append([vrf["name"] , vrf["vrf_id"]])
    table = columnar(rootScopes, headers, no_borders=False)
    print(table)

def GetAllSubScopeNames(scopes, name):
    subScopeNames = []
    try:
        for scope in scopes: 
            if name in scope["name"]:
                subScopeNames.append(scope["name"])
            else: continue
        return subScopeNames
    except:
        print(URED + "App Scope {name} not found".format(name=name))


def CreateInventory(rc, scope_name, filter_name, filter_queries):
			scopes = GetApplicationScopes(rc)
			scope_id = GetAppScopeId(scopes,scope_name)
			inventories = GetInventories(rc)
			filter_queries['filters'].pop(0)
			print(CGREEN + "\nBuilding inventory: "+CYELLOW+filter_name+ CGREEN + " under Scope " +CYELLOW+scope_name+ CEND)
			req_payload = {
			"app_scope_id": scope_id,
			"name": filter_name,
			"query": filter_queries
			}
			resp = rc.post("/filters/inventories", json_body=json.dumps(req_payload))
			parsed_resp = json.loads(resp.content)
			if resp.status_code == 200:
				inventory_id = str(parsed_resp["id"])
				print(Cyan + "\nInventory: "+CYELLOW+filter_name+ Cyan + " has been created" + CEND)
			else:
				print("Error occured during sub scope creation")
				print("Error code: "+str(resp.status_code))
				print("Content: ")
				print(resp.content)
				sys.exit(3)
			return filter_name, inventory_id


def CreateCluster(rc, app_name, appID, cluster):
	#Create new cluster under App. Return cluster_name and cluster_id
	app_versions = GetAppVersions(rc,appID)
	version = GetLatestVersion(app_versions)
	if cluster['cluster_queries'] == []:
		req_payload = {
	"name": cluster['name'],
	"version": version,
	"description": "Created by API",
	"approved": True,
	"query": cluster ['short_query']
		}
	else: 
		req_payload = {
		"name": cluster['name'],
		"version": version,
		"description": "Created by API",
		"approved": True,
		"query":{
		"type": "or",
		"filters": cluster['cluster_queries'] 
			}
			}

	print (req_payload)
	print("Adding cluster "+ CYELLOW+cluster['name'] + " into your app "+CYELLOW+app_name + CEND)
	resp = rc.post('/applications/' + appID+ '/clusters', json_body=json.dumps(req_payload))
	parsed_resp = json.loads(resp.content)
	if resp.status_code == 200:
		cluster_id = str(parsed_resp["id"])
		print("\nCluster: "+ CYELLOW+cluster['name'] + " with ID " +CYELLOW+cluster_id+ " has been added into your app "+CYELLOW+app_name + CEND)
	else:
		print("Error occured during cluster creation")
		print("Error code: "+str(resp.status_code))
		print("Content: ")
		print(resp.content)
		sys.exit(3)
	return cluster['name'], cluster_id


def CreateAbsolutePolicy(rc, app_name, appID, inventories, policy):
	#Add Absolute policy into application. Return: Policy_ID
	app_versions = GetAppVersions(rc,appID)
	version = GetLatestVersion(app_versions)
	prov_id = GetInventoriesId(inventories, policy['provider_filter_name'])
	con_id = GetInventoriesId(inventories, policy['consumer_filter_name'])
	priority = policy['priority']
	policy_action = policy['action']
	l4_params = []
	start_port = "" 
	end_port = ""
	for rule in policy['l4_params']:
		if rule['proto'] == 1:
			l4_params = [{ "proto" : 1 }]
		if rule['proto'] == "null":
			l4_params = [{ "proto" : null }]
		else:
			if 'port' in rule:
				start_port = str(rule['port'][0])
				end_port = str(rule['port'][1])
				l4_params = [{
					"proto" : rule['proto'],
					"start_port" : start_port,
					"end_port" : start_port
				}]

	print(CGREEN +"Adding Default Policy into your application "+CYELLOW+app_name+ CEND)
	req_payload = {
		"version": version,
		"policy_action" : policy_action,
		"priority" : priority,
		"consumer_filter_id" : con_id,
		"provider_filter_id" : prov_id,
		"l4_params": l4_params
	}
	resp = rc.post('/applications/' + appID +'/absolute_policies', json_body=json.dumps(req_payload))
	parsed_resp = json.loads(resp.content)
	if resp.status_code == 200:
		Policy_id = str(parsed_resp["id"])
		print(Cyan + "\nDefault Policy with ID " +CYELLOW+Policy_id + Cyan +" has just been added to your application " +CYELLOW+app_name+ CEND)
	else:
		print("Error occured during application creation")
		print("Error code: "+str(resp.status_code))
		print("Content: ")
		print(resp.content)
		sys.exit(3)
	return Policy_id

def CreateDefaultPolicy(rc, app_name, appID, inventories, policy):
	#Add default policy into application. Return: Policy_ID
	app_versions = GetAppVersions(rc,appID)
	version = GetLatestVersion(app_versions)
	prov_id = GetInventoriesId(inventories, policy['provider_filter_name'])
	con_id = GetInventoriesId(inventories, policy['consumer_filter_name'])
	priority = policy['priority']
	policy_action = policy['action']
	l4_params = []
	start_port = "" 
	end_port = ""
	for rule in policy['l4_params']:
		if rule['proto'] == 1:
			l4_params = [{ "proto" : 1 }]
		if rule['proto'] == "null":
			l4_params = [{ "proto" : null }]
		else:
			if 'port' in rule:
				start_port = str(rule['port'][0])
				end_port = str(rule['port'][1])
				l4_params = [{
					"proto" : rule['proto'],
					"start_port" : start_port,
					"end_port" : start_port
				}]

	print(CGREEN +"Adding Default Policy into your application "+CYELLOW+app_name+ CEND)
	req_payload = {
		"version": version,
		"policy_action" : policy_action,
		"priority" : priority,
		"consumer_filter_id" : con_id,
		"provider_filter_id" : prov_id,
		"l4_params": l4_params
	}
	resp = rc.post('/applications/' + appID +'/default_policies', json_body=json.dumps(req_payload))
	parsed_resp = json.loads(resp.content)
	if resp.status_code == 200:
		Policy_id = str(parsed_resp["id"])
		print(Cyan + "\nDefault Policy with ID " +CYELLOW+Policy_id + Cyan +" has just been added to your application " +CYELLOW+app_name+ CEND)
	else:
		print("Error occured during application creation")
		print("Error code: "+str(resp.status_code))
		print("Content: ")
		print(resp.content)
		sys.exit(3)
	return Policy_id

def CreateApp(rc, scopes, scope, catch_all):
	"""Create Apps Workspace under Scope without policy, if you want to add policies, use function in Policies folder
    Returns:
        Apps ID, Apps Workspace Name 
    """
	apps_name = input(CGREEN +"\nWhat is the name of your apps under " + scope + " scope you want to create: ")
	app_scope_id = GetAppScopeId(scopes,scope)
	print("Building Application: "+CYELLOW+apps_name+ " under Scope " +CYELLOW+scope+ " without policy for you" + CEND)
	req_payload = {
	"name": apps_name,
	"app_scope_id": app_scope_id,
	"description": "Created by Tetration API",
	"primary": False,
	"alternate_query_mode": True,
	"enforcement_enabled": False,
	"absolute_policies": [],
	"default_policies": [],
	"catch_all_action": catch_all}
	resp = rc.post('/applications', json_body=json.dumps(req_payload))
	parsed_resp = json.loads(resp.content)
	if resp.status_code == 200:
		apps_id = str(parsed_resp["id"])
		print("\nApplication: "+CYELLOW+apps_name+ " with ID " +CYELLOW+apps_id +" has been created. Ready to import policies from JSON file" + CEND)
	else:
		print("Error occured during application creation")
		print("Error code: "+str(resp.status_code))
		print("Content: ")
		print(resp.content)
		sys.exit(3)
	return apps_name, apps_id

def main():
	rc = CreateRestClient()
	AllApps = GetApps(rc)
	scopes = GetApplicationScopes(rc)
	apps = []
	if args.policies is None:
		print('%% No Policies Configuration file given - connecting to Tetration to download')
		appIDs = selectTetApps(AllApps)
		downloadPolicies(rc, appIDs)
	else:
	# Load in the configuration
		try:
			with open(args.policies) as config_file:
				apps.append(json.load(config_file))
		except IOError:
			print('%% Could not load configuration file')
			return
		except ValueError:
			print('Could not load improperly formatted configuration file')
			return
	for app in apps:
		print (Cyan +"Here are all the scopes in the cluster: " + CEND)
		ShowScopes(scopes)
		choice = input (CGREEN +"Which parent Scope (Number) you want to create Application workspace to import the policies for app " + app['name']+ ": " + CEND)
		scope = scopes[int(choice)-1]['name']
		app_name, appID = CreateApp(rc, scopes,scope, app['catch_all_action'])

		if 'clusters' in app.keys():
		    clusters = app['clusters']
		    for cluster in clusters:
		        CreateCluster(rc, app_name, appID, cluster)

		if 'inventory_filters' in app.keys():
			filters = app['inventory_filters']
			for invfilter in filters: 
				if invfilter['filter_type'] == "UserInventoryFilter": CreateInventory(rc, scope, invfilter['name'], invfilter['query'])
				if invfilter['filter_type'] == "AppScope": print (CRED + "Sorry!!! This script can not create scopes, and your JSON policies have policies with scopes. You will need to create scope tree to match with the original scopes and run ADM to get the policies!!!" + CEND)
		
		inventories = GetInventories(rc)

		if 'default_policies' in app.keys():
			policies = app['default_policies']
			for policy in policies:
				CreateDefaultPolicy(rc, app_name, appID, inventories, policy)

		if 'absolute_policies' in app.keys():
			policies = app['absolute_policies']
			for policy in policies:
				CreateAbsolutePolicy(rc, app_name, appID, inventories, policy)

				

if __name__ == "__main__":
	main()