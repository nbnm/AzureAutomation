import time
import sys
import requests
import json
import re

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.consumption.operations import BudgetsOperations
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.consumption import ConsumptionManagementClient
import automationassets

# for azure Runas credentials
def get_automation_runas_credential(runas_connection):
    from OpenSSL import crypto
    import binascii
    from msrestazure import azure_active_directory
    import adal
    import automationassets

    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    pks12_cert = crypto.load_pkcs12(cert)
    pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM,pks12_cert.get_privatekey())

    # Get run as connection information for the Azure Automation service principal
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    resource ="https://management.core.windows.net/"
    authority_url = ("https://login.microsoftonline.com/"+tenant_id)
    context = adal.AuthenticationContext(authority_url)
    return azure_active_directory.AdalAuthentication(
    lambda: context.acquire_token_with_client_certificate(
            resource,
            application_id,
            pem_pkey,
            thumbprint)
    )

# Return token based on Azure automation Runas connection
def get_automation_runas_token(runas_connection):
    """ Returs a token that can be used to authenticate against Azure resources """
    from OpenSSL import crypto
    import adal

    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    sp_cert = crypto.load_pkcs12(cert)
    pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, sp_cert.get_privatekey())

    # Get run as connection information for the Azure Automation service principal
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    resource = "https://management.core.windows.net/"
    authority_url = ("https://login.microsoftonline.com/" + tenant_id)
    context = adal.AuthenticationContext(authority_url)
    azure_credential = context.acquire_token_with_client_certificate(
        resource,
        application_id,
        pem_pkey,
        thumbprint)

    # Return the token
    return azure_credential.get('accessToken')

# Create a consumption budget
def createbudget(token,subscription, scope,budget_name):
    # Parameters need for API
    print ("Starting createbudget")
    budgetUrl = "https://management.azure.com{}/providers/Microsoft.Consumption/budgets/{}?api-version=2019-10-01".format(scope,budget_name)
    print ("budgetUrl = "+budgetUrl)
    body = automationassets.get_automation_variable("SampleBudget")
    response = requests.put(budgetUrl, allow_redirects=False, headers = {'Authorization': 'Bearer %s' %token , 'Content-type':'application/json'}, data=body)

# Return true if proper budget already exists
def checkifbudgetexists(token,subscription, scope, budget_name):
    print ("Starting checkifbudgetexists")
    # Parameters need for API
    budgetUrl = "https://management.azure.com{}/providers/Microsoft.Consumption/budgets/{}?api-version=2019-10-01".format(scope,budget_name)
    print ("budgetUrl = " + budgetUrl)

    response = requests.get(budgetUrl, headers = {'Authorization': 'Bearer %s' %token , 'Content-type':'application/json'})

    if response.status_code == 404:
        print('Budget doesnt exist')
        return 0
    print('Budget exists')
    return 1

def get_resource_group_from_webhook(in_str):    
    VALIDATION_PATTERN = '"action":"Microsoft.Resources/subscriptions/resourceGroups/write"'
    SCOPE_PATTERN_START = '{\"scope\":"' 
    SCOPE_PATTERN_END = '",\"action\"'
    if in_str !="":
        # Validate that webhook refers to resource group creation
        if VALIDATION_PATTERN in in_str:
            scope = re.search(SCOPE_PATTERN_START + '(.*)' + SCOPE_PATTERN_END, in_str)
            print ("scope " + scope.group(1))
            if scope.group(1) !="":
                return scope.group(1)
    print("ERROR: RG was not found in Webhook ")
    return ""



def main():

    #resource_group_name = str(sys.argv[1])
    #vm_name = str(sys.argv[2])

    rg_scope = get_resource_group_from_webhook(sys.argv[1])
    print("DEBUG: - input from webhook" + str(sys.argv[1]))

    if rg_scope!="":
        
        #get RG Name
        rg_name = rg_scope[rg_scope.rindex('/')+1:]
        if rg_name!="":

            runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
            token = get_automation_runas_token(runas_connection)

            #For debug create resource manually
            # az_credential = get_automation_runas_credential(runas_connection)
            # subscription_client = SubscriptionClient(az_credential)

            # subscription = next(subscription_client.subscriptions.list())
            # print(subscription.subscription_id)

            # TIME = str(time.time()).replace('.','')
            # GROUP_NAME = "testconsumption" + TIME
            # CONSUMPTION = "consumption" + TIME

            # resource_client = ResourceManagementClient(
            #    az_credential,
            #    subscription.subscription_id
            # )
            # consumption_client = ConsumptionManagementClient(
            #    az_credential,
            #     subscription.subscription_id
            #)     
            #SCOPE = '/subscriptions/{}/resourceGroups/{}'.format(subscription.subscription_id, GROUP_NAME)
            #resource_client.resource_groups.create_or_update(
            #    GROUP_NAME,
            #    {"location": "eastus"}
            #)
            budgetName = 't1a-500-' + rg_name
            SCOPE = rg_scope
            subscription_id = rg_scope.split('/')[2]
        
            # !!! Doesn't work due to bug in Azure SDK
            #consumption = consumption_client.budgets.create_or_update(
            #    SCOPE,
            #    budgetName,
            #    json.loads(automationassets.get_automation_variable("SampleBudget"))     
            #)
            if subscription_id !="":
                if not checkifbudgetexists(token,subscription_id,SCOPE,budgetName):
                    createbudget(token,subscription_id, SCOPE,budgetName)
    elseif: print("ERROR: - RG scope is empty")



if __name__ == "__main__":
    main()