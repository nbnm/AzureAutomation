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

    runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
    token = get_automation_runas_token(runas_connection)
    az_credential = get_automation_runas_credential(runas_connection)
    subscription_client = SubscriptionClient(az_credential)
    subscription = next(subscription_client.subscriptions.list())

    resource_client = ResourceManagementClient(
      az_credential,
      subscription.subscription_id
    )

    group_list = resource_client.resource_groups.list()

    subscription_id = subscription.subscription_id

    for group in list(group_list):
        print("group.name = " + group.name)
        print("group.location = " + group.location)
        SCOPE = '/subscriptions/{}/resourceGroups/{}'.format(subscription_id, group.name)
        print (SCOPE)
        rg_name = group.name
        budgetName = 't1a-500-' + rg_name

        if not checkifbudgetexists(token,subscription_id,SCOPE,budgetName):
            #print ('want to create for '+SCOPE+' with name'+budgetName )
            createbudget(token,subscription_id, SCOPE,budgetName)




if __name__ == "__main__":
    main()