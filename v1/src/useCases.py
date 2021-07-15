from .env.api import *
from django.http import HttpResponse, JsonResponse
from .controlFunctions import *
import time
from .env import api_settings as Settings

import json
import re

import uuid


LENGTH_SESSIONID = 36   # 32 + 4 (hyphens)
LENGTH_UUID = 32

REQUEST_RESPONSE_200_OK = 200
REQUEST_RESPONSE_401_UNAUTHORIZED = 401

RETRIEVE_MODULE_VALID_METHODS = ['eIDAS', 'eduGAIN', 'eMRTD']

DERIVE_MODULE_VALID_METHODS = ['UUID'] 

DS_MODULE_VALID_METHODS = ['Browser', 'googleDrive', 'oneDrive', 'Mobile']

SSI_LINK_MODULE_VALID_METHODS = 'uPort'

VC_DEFINITIONS = 'vcDefinitions'

UNIQUE_PROVIDERS = 'uniqueProviders'

VC_ISSUE_MODULE_VALID_METHODS = ['eIDAS', 'eduGAIN', 'eMRTD', 'eIDAS-eduGAIN']

VC_ISSUE_SSI_ID_VALID_METHODS = 'uPort'

EMRTD_VALID_METHODS = ['eMRTD']

LINK_MODULE_VALID_METHODS = ['autoSEAL', 'manualXYZ']


"""API TEST (Get)"""
def api_test(request):
    return JsonResponse(JsonConstructor(_UUID="12345678901234567890123456789012", _address="https://seal.uma.es/seal", _msToken="abcdef"))

    # OK    
    #return JsonResponse(JsonConstructor(_UUID="12345678901234567890123456789012"))


"""TEST API HELP"""
def api_help(request):

    return JsonResponse({"name": "help function", "url": "seal.uma.es/api/v1"})
    

"""Token Validate"""
def api_tokenValidate(request):

    API_TOKEN_VALIDATE_DEBUG_CODE = "api_TKN_VAL - "
    
    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.POST.get('UUID',None) == None:
            raise JsonVariables.Exceptions.RequestNeedsUUID
            
        UUID = request.POST['UUID']

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId
        
        if request.POST.get('msToken', None) == None:
            raise JsonVariables.Exceptions.RequestNeedsmsToken

        msToken = request.POST['msToken']

        if not re.compile(JsonVariables.Regex.REGEX_MSTOKEN).match(msToken):
            raise JsonVariables.Exceptions.ErrorTokenDoesntFitRegex

        cl_token = Cl_token()

        response_validation = cl_token.validate(msToken, cl_session.sessionID)
        print(response_validation)

        if not response_validation.status_code == 200:
            raise JsonVariables.Exceptions.TokenResponseFailed

        jwt_result = jwt.decode(msToken, verify=False)

        if not len(jwt_result.get('sessionId')) == LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.TokenResponseFailed


        return JsonResponse(JsonConstructor(_msToken=msToken), status=200)


    except JsonVariables.Exceptions.MethodNotValid:
            print(API_TOKEN_VALIDATE_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
            return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_TOKEN_VALIDATE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_TOKEN_VALIDATE_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_MSTOKEN_VALIDATION_FAILED), status=502)


    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_TOKEN_VALIDATE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_TOKEN_VALIDATE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)


    except JsonVariables.Exceptions.RequestNeedsmsToken:
        print(API_TOKEN_VALIDATE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_MSTOKEN)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_MSTOKEN), status=400)


    except JsonVariables.Exceptions.ErrorTokenDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_TOKEN_VALIDATE_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_MSTOKEN_VALIDATION_FAILED), status=400)


    except JsonVariables.Exceptions.TokenResponseFailed:
        # Tracing details error only on the server 
        print(API_TOKEN_VALIDATE_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_MSTOKEN_VALIDATION_FAILED), status=502)


"""Session Start"""
def api_sessionStart(request):

    API_SESSION_START_DEBUG_CODE = "api_SES_STA - "

    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid
    
        UUID = getUUID()

        if UUID == 'UUID_ERROR':
            raise JsonVariables.Exceptions.ErrorGeneratingUUID

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId


        return JsonResponse(JsonConstructor(_UUID=UUID), status=200)


    except JsonVariables.Exceptions.MethodNotValid:
        print(API_SESSION_START_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.ErrorGeneratingUUID:
        # Tracing details error only on the server 
        print(API_SESSION_START_DEBUG_CODE + JsonVariables.Error.ERROR_GENERATING_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SESSION_NOT_CREATED), status=500)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server
        print(API_SESSION_START_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SESSION_NOT_CREATED), status=502)


    except:
        print(API_SESSION_START_DEBUG_CODE + JsonVariables.Error.ERROR_SESSION_NOT_CREATED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SESSION_NOT_CREATED), status=500)
        

"""Datastore Load"""
def api_datastoreLoad(request, moduleID):

    API_DS_LOAD_DEBUG_CODE = "api_DS_LOAD - "
    
    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.get_signed_cookie('UUID', None):
            UUID = request.get_signed_cookie('UUID')

        elif request.POST.get('UUID',None):
            UUID = request.POST['UUID']
        
        else:
            raise JsonVariables.Exceptions.RequestNeedsUUID

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        if moduleID == None:
            raise JsonVariables.Exceptions.RequestNeedsModuleID

        if moduleID not in DS_MODULE_VALID_METHODS:
            raise JsonVariables.Exceptions.RequestWithInvalidModuleID

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId

        # Logic of the identity retrieve request        
        cl_callback = Cl_callback()

        r_callback = cl_callback.callback(cl_session.sessionID, Settings.Prod.SEAL_ENDPOINT + '/tokenValidate='+UUID)

        if r_callback.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.CallbackResponseFailed
        
        cl_persistence = Cl_persistence()

        r_persistence = cl_persistence.load(cl_session.sessionID, moduleID)

        if r_persistence.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.PersistenceResponseFailed

        response_address = r_persistence.json().get('access').get('address')
        response_sessionToken = r_persistence.json().get('payload')        
        response_bindingMethod = r_persistence.json().get('access').get('binding')

        if not re.compile(JsonVariables.Regex.REGEX_ADDRESS).match(response_address):
            raise JsonVariables.Exceptions.ErrorAddressDoesntFitRegex

        if not re.compile(JsonVariables.Regex.REGEX_MSTOKEN).match(response_sessionToken):
            raise JsonVariables.Exceptions.ErrorTokenDoesntFitRegex

        if response_bindingMethod not in ['HTTP-POST-REDIRECT','HTTP-GET-REDIRECT']:
            raise JsonVariables.Exceptions.ErrorBindingDoesntFitList

        return JsonResponse(JsonConstructor(_address=response_address, _msToken=response_sessionToken, _bindingMethod=response_bindingMethod), status=200)

    except JsonVariables.Exceptions.MethodNotValid:
            print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
            return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_LOAD_FAILED), status=502)


    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)


    except JsonVariables.Exceptions.RequestNeedsModuleID:
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID), status=400)


    except JsonVariables.Exceptions.RequestWithInvalidModuleID:
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID), status=400)


    except JsonVariables.Exceptions.CallbackResponseFailed:
        # Tracing details error only on the server 
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_CALLBACK_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_LOAD_FAILED), status=502)


    except JsonVariables.Exceptions.PersistenceResponseFailed:
        # Tracing details error only on the server 
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_PERSISTENCE_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_LOAD_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorTokenDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_LOAD_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorAddressDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_ADDRESS_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_LOAD_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorBindingDoesntFitList:
        # Tracing details error only on the server 
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_BINDING_DOESNT_FIT_LIST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_LOAD_FAILED), status=502)

    except:
        print(API_DS_LOAD_DEBUG_CODE + JsonVariables.Error.ERROR_PERSISTENCE_LOAD_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_LOAD_FAILED), status=500)


"""Datastore Storage"""
def api_datastoreStore(request, moduleID):

    API_DS_STORE_DEBUG_CODE = "api_DS_STORE - "
    
    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.get_signed_cookie('UUID', None):
            UUID = request.get_signed_cookie('UUID')

        elif request.POST.get('UUID',None):
            UUID = request.POST['UUID']
        
        else:
            raise JsonVariables.Exceptions.RequestNeedsUUID

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        if moduleID == None:
            raise JsonVariables.Exceptions.RequestNeedsModuleID

        if moduleID not in DS_MODULE_VALID_METHODS:
            raise JsonVariables.Exceptions.RequestWithInvalidModuleID

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId

        # Logic of the identity retrieve request        
        cl_callback = Cl_callback()

        r_callback = cl_callback.callback(cl_session.sessionID, Settings.Prod.SEAL_ENDPOINT + '/tokenValidate='+UUID)

        if r_callback.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.CallbackResponseFailed
        
        cl_persistence = Cl_persistence()

        r_persistence = cl_persistence.store(cl_session.sessionID, moduleID)

        if r_persistence.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.PersistenceResponseFailed

        response_address = r_persistence.json().get('access').get('address')
        response_sessionToken = r_persistence.json().get('payload')        
        response_bindingMethod = r_persistence.json().get('access').get('binding')

        if not re.compile(JsonVariables.Regex.REGEX_ADDRESS).match(response_address):
            raise JsonVariables.Exceptions.ErrorAddressDoesntFitRegex

        if not re.compile(JsonVariables.Regex.REGEX_MSTOKEN).match(response_sessionToken):
            raise JsonVariables.Exceptions.ErrorTokenDoesntFitRegex

        if response_bindingMethod not in ['HTTP-POST-REDIRECT','HTTP-GET-REDIRECT']:
            raise JsonVariables.Exceptions.ErrorBindingDoesntFitList

        return JsonResponse(JsonConstructor(_address=response_address, _msToken=response_sessionToken, _bindingMethod=response_bindingMethod), status=200)

    except JsonVariables.Exceptions.MethodNotValid:
            print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
            return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_STORE_FAILED), status=502)

    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)


    except JsonVariables.Exceptions.RequestNeedsModuleID:
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID), status=400)


    except JsonVariables.Exceptions.RequestWithInvalidModuleID:
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID), status=400)


    except JsonVariables.Exceptions.CallbackResponseFailed:
        # Tracing details error only on the server 
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_CALLBACK_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_STORE_FAILED), status=502)


    except JsonVariables.Exceptions.PersistenceResponseFailed:
        # Tracing details error only on the server 
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_PERSISTENCE_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_STORE_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorTokenDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_STORE_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorAddressDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_ADDRESS_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_STORE_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorBindingDoesntFitList:
        # Tracing details error only on the server 
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_BINDING_DOESNT_FIT_LIST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_STORE_FAILED), status=502)

    except:
        print(API_DS_STORE_DEBUG_CODE + JsonVariables.Error.ERROR_PERSISTENCE_STORE_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_PERSISTENCE_STORE_FAILED), status=500)


"""SSI Link"""
def api_ssiLink(request):

    API_SSI_LINK_DEBUG_CODE = "api_SSI_LINK - "
    
    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.get_signed_cookie('UUID', None):
            UUID = request.get_signed_cookie('UUID')

        elif request.POST.get('UUID',None):
            UUID = request.POST['UUID']
        
        else:
            raise JsonVariables.Exceptions.RequestNeedsUUID

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        moduleID = SSI_LINK_MODULE_VALID_METHODS

        # Since the moduleID is hardcode in the backend, there is no need to check its value
        # if moduleID == None:
        #     raise JsonVariables.Exceptions.RequestNeedsModuleID

        # if moduleID not in DS_MODULE_VALID_METHODS:
        #     raise JsonVariables.Exceptions.MethodNotValid

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId

        # Logic of the identity retrieve request        
        cl_callback = Cl_callback()

        r_callback = cl_callback.callback(cl_session.sessionID, Settings.Prod.SEAL_ENDPOINT + '/tokenValidate='+UUID)

        if r_callback.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.CallbackResponseFailed
        
        cl_ident = Cl_ident()

        r_ident = cl_ident.sourceRetrieve(cl_session.sessionID, moduleID)

        if r_ident.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.SSILinkResponseFailed

        response_address = r_ident.json().get('access').get('address')
        response_sessionToken = r_ident.json().get('payload')        
        response_bindingMethod = r_ident.json().get('access').get('binding')

        if not re.compile(JsonVariables.Regex.REGEX_ADDRESS).match(response_address):
            raise JsonVariables.Exceptions.ErrorAddressDoesntFitRegex

        if not re.compile(JsonVariables.Regex.REGEX_MSTOKEN).match(response_sessionToken):
            raise JsonVariables.Exceptions.ErrorTokenDoesntFitRegex

        if response_bindingMethod not in ['HTTP-POST-REDIRECT']:
            raise JsonVariables.Exceptions.ErrorBindingDoesntFitList

        return JsonResponse(JsonConstructor(_address=response_address, _msToken=response_sessionToken, _bindingMethod=response_bindingMethod), status=200)

    except JsonVariables.Exceptions.MethodNotValid:
            print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
            return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SSI_LINK_FAILED), status=502)

    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)


    except JsonVariables.Exceptions.RequestNeedsModuleID:
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID), status=400)


    # except JsonVariables.Exceptions.RequestWithInvalidModuleID:
    #     print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID)
    #     return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID), status=400)


    except JsonVariables.Exceptions.CallbackResponseFailed:
        # Tracing details error only on the server 
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_CALLBACK_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SSI_LINK_FAILED), status=502)


    except JsonVariables.Exceptions.SSILinkResponseFailed:
        # Tracing details error only on the server 
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_PERSISTENCE_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SSI_LINK_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorTokenDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SSI_LINK_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorAddressDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_ADDRESS_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SSI_LINK_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorBindingDoesntFitList:
        # Tracing details error only on the server 
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_BINDING_DOESNT_FIT_LIST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SSI_LINK_FAILED), status=502)

    except:
        print(API_SSI_LINK_DEBUG_CODE + JsonVariables.Error.ERROR_SSI_LINK_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_SSI_LINK_FAILED), status=500)


"""Retrieve Id. Data"""
def api_retrieveIdData(request):
    
    API_RETRIEVE_ID_DATA_DEBUG_CODE = "api_RET_DAT - "
    

    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.get_signed_cookie('UUID', None):
            UUID = request.get_signed_cookie('UUID')

        elif request.POST.get('UUID',None):
            UUID = request.POST['UUID']
        
        else:
            raise JsonVariables.Exceptions.RequestNeedsUUID

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        if request.POST.get('moduleID',None) == None:
            raise JsonVariables.Exceptions.RequestNeedsModuleID

        moduleID = request.POST['moduleID']

        if moduleID not in RETRIEVE_MODULE_VALID_METHODS:
            raise JsonVariables.Exceptions.RequestWithInvalidModuleID

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId

        # Logic of the identity retrieve request        
        cl_callback = Cl_callback()

        r_callback = cl_callback.callback(cl_session.sessionID, Settings.Prod.SEAL_ENDPOINT + '/tokenValidate='+UUID)

        if r_callback.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.CallbackResponseFailed

        cl_auth = Cl_auth()

        r_auth = cl_auth.moduleLogin(cl_session.sessionID, moduleID)

        if r_auth.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.AuthResponseFailed

        response_address = r_auth.json().get('access').get('address')
        response_sessionToken = r_auth.json().get('payload')        
        response_bindingMethod = r_auth.json().get('access').get('binding')

        if not re.compile(JsonVariables.Regex.REGEX_ADDRESS).match(response_address):
            raise JsonVariables.Exceptions.ErrorAddressDoesntFitRegex

        if not re.compile(JsonVariables.Regex.REGEX_MSTOKEN).match(response_sessionToken):
            raise JsonVariables.Exceptions.ErrorTokenDoesntFitRegex

        if response_bindingMethod not in ['HTTP-POST-REDIRECT']:
            raise JsonVariables.Exceptions.ErrorBindingDoesntFitList


        return JsonResponse(JsonConstructor(_address=response_address, _msToken=response_sessionToken, _bindingMethod=response_bindingMethod), status=200)


    except JsonVariables.Exceptions.MethodNotValid:
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_RETRIEVE_IDENTITY_FAILED), status=502)

    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)


    except JsonVariables.Exceptions.RequestNeedsModuleID:
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID), status=400)


    except JsonVariables.Exceptions.RequestWithInvalidModuleID:
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID), status=400)


    except JsonVariables.Exceptions.CallbackResponseFailed:
        # Tracing details error only on the server 
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_CALLBACK_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_RETRIEVE_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.AuthResponseFailed:
        # Tracing details error only on the server 
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_AUTH_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_RETRIEVE_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorTokenDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_RETRIEVE_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorAddressDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_ADDRESS_DOESNT_FIT_REGEX) 
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_RETRIEVE_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorBindingDoesntFitList:
        # Tracing details error only on the server 
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_BINDING_DOESNT_FIT_LIST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_RETRIEVE_IDENTITY_FAILED), status=502)

    except:
        print(API_RETRIEVE_ID_DATA_DEBUG_CODE + JsonVariables.Error.ERROR_RETRIEVE_IDENTITY_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_RETRIEVE_IDENTITY_FAILED), status=500)
        
        
"""Derive Identifier"""
def api_deriveIdentifier(request):
    
    API_DERIVE_ID_DEBUG_CODE = "api_DER_ID - "
    
    
    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.get_signed_cookie('UUID', None):
            UUID = request.get_signed_cookie('UUID')

        elif request.POST.get('UUID',None):
            UUID = request.POST['UUID']
        
        else:
            raise JsonVariables.Exceptions.RequestNeedsUUID

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        if request.POST.get('moduleID',None) == None:
            raise JsonVariables.Exceptions.RequestNeedsModuleID

        moduleID = request.POST['moduleID']

        if moduleID not in DERIVE_MODULE_VALID_METHODS:
            raise JsonVariables.Exceptions.RequestWithInvalidModuleID

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId

        # Logic of the identity retrieve request        
        cl_callback = Cl_callback()

        r_callback = cl_callback.callback(cl_session.sessionID, Settings.Prod.SEAL_ENDPOINT + '/tokenValidate='+UUID)

        if r_callback.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.CallbackResponseFailed
        
        cl_ident = Cl_ident()

        r_ident = cl_ident.derivationGenerate(cl_session.sessionID, moduleID)

        if r_ident.status_code != REQUEST_RESPONSE_200_OK:
            if r_ident.status_code == REQUEST_RESPONSE_401_UNAUTHORIZED:
                raise JsonVariables.Exceptions.IdentResponseUnauthorized
            else:
                raise JsonVariables.Exceptions.IdentResponseFailed

        response_address = r_ident.json().get('access').get('address')
        response_sessionToken = r_ident.json().get('payload')        
        response_bindingMethod = r_ident.json().get('access').get('binding')

        if not re.compile(JsonVariables.Regex.REGEX_ADDRESS).match(response_address):
            raise JsonVariables.Exceptions.ErrorAddressDoesntFitRegex

        if not re.compile(JsonVariables.Regex.REGEX_MSTOKEN).match(response_sessionToken):
            raise JsonVariables.Exceptions.ErrorTokenDoesntFitRegex

        if response_bindingMethod not in ['HTTP-POST-REDIRECT']:
            raise JsonVariables.Exceptions.ErrorBindingDoesntFitList

        return JsonResponse(JsonConstructor(_address=response_address, _msToken=response_sessionToken, _bindingMethod=response_bindingMethod), status=200)

    except JsonVariables.Exceptions.MethodNotValid:
            print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
            return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_DERIVE_IDENTITY_FAILED), status=502)

    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)


    except JsonVariables.Exceptions.RequestNeedsModuleID:
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID), status=400)


    except JsonVariables.Exceptions.RequestWithInvalidModuleID:
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID), status=400)


    except JsonVariables.Exceptions.CallbackResponseFailed:
        # Tracing details error only on the server 
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_CALLBACK_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_DERIVE_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.IdentResponseFailed:
        # Tracing details error only on the server 
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_IDENT_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_DERIVE_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.IdentResponseUnauthorized:
        # Tracing details error only on the server 
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_IDENT_RESPONSE_UNAUTHORIZED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_DERIVE_IDENTITY_FAILED), status=401)


    except JsonVariables.Exceptions.ErrorTokenDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_DERIVE_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorAddressDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_ADDRESS_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_DERIVE_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorBindingDoesntFitList:
        # Tracing details error only on the server 
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_BINDING_DOESNT_FIT_LIST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_DERIVE_IDENTITY_FAILED), status=502)

    except:
        print(API_DERIVE_ID_DEBUG_CODE + JsonVariables.Error.ERROR_DERIVE_IDENTITY_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_DERIVE_IDENTITY_FAILED), status=500)
        

"""Identity Reconciliation (Link)"""
def api_identityLink(request):

    API_LINK_ID_DEBUG_CODE = "api_LNK_ID - "
    
    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.get_signed_cookie('UUID', None):
            UUID = request.get_signed_cookie('UUID')

        elif request.POST.get('UUID',None):
            UUID = request.POST['UUID']
        
        else:
            raise JsonVariables.Exceptions.RequestNeedsUUID

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        if request.POST.get('moduleID',None) == None:
            raise JsonVariables.Exceptions.RequestNeedsModuleID

        moduleID = request.POST['moduleID']

        if moduleID not in LINK_MODULE_VALID_METHODS:
            raise JsonVariables.Exceptions.RequestWithInvalidModuleID

        if request.POST.get('identityIDa',None) == None or request.POST.get('identityIDb',None) == None:
            raise JsonVariables.Exceptions.RequestNeedsIdentityID

        identityIDa = request.POST['identityIDa']
        identityIDb = request.POST['identityIDb']

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId

        # Logic of the identity retrieve request        
        cl_callback = Cl_callback()

        r_callback = cl_callback.callback(cl_session.sessionID, Settings.Prod.SEAL_ENDPOINT + '/tokenValidate='+UUID)

        if r_callback.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.CallbackResponseFailed
        
        cl_ident = Cl_ident()

        r_ident = cl_ident.mgrList(cl_session.sessionID)

        if not r_ident.status_code == REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.IdentResponseFailed

        #identities = cl_ident.jsonParser(r_ident)
        identities = r_ident.json()

        if not identities:
            raise JsonVariables.Exceptions.IdentitiesListEmpty

        for index in range(0, len(identities)):
            result_data = json.loads(identities[index].get('data'))
            identities[index].update({'data': result_data})

        identityA = list(filter(lambda identity: unquote(identity['id']) == identityIDa, identities))
        identityB = list(filter(lambda identity: unquote(identity['id']) == identityIDb, identities))

        # assert(len(identityA) > 0 and len(identityB) > 0)
        if not identityA or not identityB:
            raise JsonVariables.Exceptions.CantRetrieveRequestedIdentities

        r_ident = cl_ident.linkingRequest(cl_session.sessionID, moduleID, identityA[0]['id'], identityB[0]['id'])
        
        if not r_ident.status_code == REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.IdentResponseFailed

        response_address = r_ident.json().get('access').get('address')
        response_sessionToken = r_ident.json().get('payload')        
        response_bindingMethod = r_ident.json().get('access').get('binding')

        if not re.compile(JsonVariables.Regex.REGEX_ADDRESS).match(response_address):
            raise JsonVariables.Exceptions.ErrorAddressDoesntFitRegex

        if not re.compile(JsonVariables.Regex.REGEX_MSTOKEN).match(response_sessionToken):
            raise JsonVariables.Exceptions.ErrorTokenDoesntFitRegex

        if response_bindingMethod not in ['HTTP-POST-REDIRECT']:
            raise JsonVariables.Exceptions.ErrorBindingDoesntFitList

        return JsonResponse(JsonConstructor(_address=response_address, _msToken=response_sessionToken, _bindingMethod=response_bindingMethod), status=200)

    except JsonVariables.Exceptions.MethodNotValid:
            print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
            return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)


    except JsonVariables.Exceptions.RequestNeedsModuleID:
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID), status=400)


    except JsonVariables.Exceptions.RequestWithInvalidModuleID:
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID), status=400)


    except JsonVariables.Exceptions.RequestNeedsIdentityID:
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_IDENTITY_ID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_IDENTITY_ID), status=400)


    except JsonVariables.Exceptions.CallbackResponseFailed:
        # Tracing details error only on the server 
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_CALLBACK_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.IdentResponseFailed:
        # Tracing details error only on the server 
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_IDENT_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.IdentitiesListEmpty:
        # Tracing details error only on the server 
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_ID_LIST_EMPTY)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.CantRetrieveRequestedIdentities:
        # Tracing details error only on the server 
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_CANT_RETRIEVE_ID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorTokenDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorAddressDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_ADDRESS_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorBindingDoesntFitList:
        # Tracing details error only on the server 
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_BINDING_DOESNT_FIT_LIST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED), status=502)

    except:
        print(API_LINK_ID_DEBUG_CODE + JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_LINK_IDENTITY_FAILED), status=500)


"""Manage Identity Data (All providers)"""
def api_identityAllList(request):
    API_ID_ALL_LIST_DEBUG_CODE = "api_ID_ALL_LIST - "

    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.get_signed_cookie('UUID', None):
            UUID = request.get_signed_cookie('UUID')

        elif request.POST.get('UUID',None):
            UUID = request.POST['UUID']
        
        else:
            raise JsonVariables.Exceptions.RequestNeedsUUID

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId
        
        cl_ident = Cl_ident()

        r_ident = cl_ident.mgrList(cl_session.sessionID)

        if not r_ident.status_code == REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.IdentResponseFailed

        identities = cl_ident.jsonParser(r_ident)

        json_identities = json.dumps(identities)

        return JsonResponse(JsonConstructor(_identities=json_identities), status=200)



    except JsonVariables.Exceptions.MethodNotValid:
            print(API_ID_ALL_LIST_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
            return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)
    

    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_ID_ALL_LIST_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_ID_ALL_LIST_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_ID_ALL_LIST_FAILED), status=502)

    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_ID_ALL_LIST_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_ID_ALL_LIST_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)
    

    except JsonVariables.Exceptions.IdentResponseFailed:
        # Tracing details error only on the server 
        print(API_ID_ALL_LIST_DEBUG_CODE + JsonVariables.Error.ERROR_IDENT_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_ID_ALL_LIST_FAILED), status=502)


    except:
        print(API_ID_ALL_LIST_DEBUG_CODE + JsonVariables.Error.ERROR_ID_ALL_LIST_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_ID_ALL_LIST_FAILED), status=500)


""" EMRTD """
def api_eMRTD(request, moduleID):

    API_EMRTD_DEBUG_CODE = "api_EMRTD - "
    
    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.get_signed_cookie('UUID', None):
            UUID = request.get_signed_cookie('UUID')

        elif request.POST.get('UUID',None):
            UUID = request.POST['UUID']
        
        else:
            raise JsonVariables.Exceptions.RequestNeedsUUID

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        if moduleID == None:
            raise JsonVariables.Exceptions.RequestNeedsModuleID

        if moduleID not in EMRTD_VALID_METHODS:
            raise JsonVariables.Exceptions.RequestWithInvalidModuleID

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId

        if request.POST.get('param_json',None) == None:
            raise JsonVariables.Exceptions.RequestNeedsDataSet

        _dataset = request.POST['param_json']

        cl_ident = Cl_ident()

        signed_dataset = DatasetSerialisedConstructor(uuid.uuid4(), _dataset)

        r_ident = cl_ident.sourceLoad(cl_session.sessionID, moduleID, signed_dataset)  

        if r_ident.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.IdentResponseFailed

        response_address = r_ident.json().get('access').get('address')
        response_sessionToken = r_ident.json().get('payload')        
        response_bindingMethod = r_ident.json().get('access').get('binding')

        if not re.compile(JsonVariables.Regex.REGEX_ADDRESS).match(response_address):
            raise JsonVariables.Exceptions.ErrorAddressDoesntFitRegex

        if not re.compile(JsonVariables.Regex.REGEX_MSTOKEN).match(response_sessionToken):
            raise JsonVariables.Exceptions.ErrorTokenDoesntFitRegex

        if response_bindingMethod not in ['HTTP-POST-REDIRECT','HTTP-GET-REDIRECT']:
            raise JsonVariables.Exceptions.ErrorBindingDoesntFitList

        generic_api = Generic()

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {'msToken': response_sessionToken}

        r_isload = generic_api.post(headers,response_address,payload)

        print('***** r_isload: ')
        print(r_isload)

        print('***** r_isload.content: ')
        print(r_isload.content)

        # TO-DO: Create a new error
        if r_isload.status_code != REQUEST_RESPONSE_200_OK:
            raise Exception

        return JsonResponse(JsonConstructor(), status=200)

    except JsonVariables.Exceptions.MethodNotValid:
            print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
            return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)

    
    except JsonVariables.Exceptions.RequestNeedsDataSet:
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_DATASET)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_DATASET), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_ID_EMRTD_FAILED), status=502)

    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)


    except JsonVariables.Exceptions.RequestNeedsModuleID:
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID), status=400)


    except JsonVariables.Exceptions.RequestWithInvalidModuleID:
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID), status=400)

    except JsonVariables.Exceptions.IdentResponseFailed:
        # Tracing details error only on the server 
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_IDENT_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_IDENT_RESPONSE_HAS_FAILED), status=502)    


    except JsonVariables.Exceptions.ErrorTokenDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_ID_EMRTD_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorAddressDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_ADDRESS_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_ID_EMRTD_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorBindingDoesntFitList:
        # Tracing details error only on the server 
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_BINDING_DOESNT_FIT_LIST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_ID_EMRTD_FAILED), status=502)

    except:
        print(API_EMRTD_DEBUG_CODE + JsonVariables.Error.ERROR_ID_EMRTD_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_ID_EMRTD_FAILED), status=500)


"""VC Issue"""
def api_vcIssue(request):

    API_VC_ISSUE_DEBUG_CODE = "api_VC_ISSUE - "
     
    try:
        if request.method != 'POST':
            raise JsonVariables.Exceptions.MethodNotValid

        if request.get_signed_cookie('UUID', None):
            UUID = request.get_signed_cookie('UUID')

        elif request.POST.get('UUID',None):
            UUID = request.POST['UUID']
        
        else:
            raise JsonVariables.Exceptions.RequestNeedsUUID

        if len(UUID) != LENGTH_UUID or not sessionExists(UUID):
            raise JsonVariables.Exceptions.RequestWithInvalidUUID

        if not sessionValid(UUID):
            raise JsonVariables.Exceptions.RequestWithOutdatedUUID

        if request.POST.get('moduleID',None) == None:
            raise JsonVariables.Exceptions.RequestNeedsModuleID

        moduleID = request.POST['moduleID']

        if moduleID not in VC_ISSUE_MODULE_VALID_METHODS:
            raise JsonVariables.Exceptions.RequestWithInvalidModuleID

        ssiID = VC_ISSUE_SSI_ID_VALID_METHODS

        cl_session = sessionControl(UUID)

        if len(cl_session.sessionID) != LENGTH_SESSIONID:
            raise JsonVariables.Exceptions.ErrorInvalidLengthSessionId

        # Logic of the identity retrieve request        
        cl_callback = Cl_callback()

        r_callback = cl_callback.callback(cl_session.sessionID, Settings.Prod.SEAL_ENDPOINT + '/tokenValidate='+UUID)

        if r_callback.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.CallbackResponseFailed

        cl_list = Cl_list()

        r_list = cl_list.getCollection(VC_DEFINITIONS).json()

        if not r_list:
            raise JsonVariables.Exceptions.ListResponseFailed
        
        VCDefinitions_list = [list(VCDefinition.keys())[0] for VCDefinition in r_list]
        VCDefinitions_list.append(VC_ISSUE_MODULE_VALID_METHODS[3].lower())

        # Appended a new vcDefinition for eidas-edugain linked identities to the ones retrieved from the APIGW:
        if moduleID.lower() not in VCDefinitions_list:
            raise JsonVariables.Exceptions.NoModuleIDinVCDefinitionsList

        VCDefinition = moduleID.lower()

        identities = uc0_02(UUID)

        # quick temporal fix for 'eidas-edugain' moduleId to 'linked' unique provider:
        if VCDefinition == VC_ISSUE_MODULE_VALID_METHODS[3].lower():
            moduleID = 'linkedID'
        # end of quick fix

        if not identities and moduleID in identities.get(UNIQUE_PROVIDERS): 
            raise JsonVariables.Exceptions.IdentitiesCantBeRetrieved
       
        cl_vcissuing = Cl_vcissuing()

        r_vcissuing = cl_vcissuing.generate(cl_session.sessionID, ssiID, VCDefinition)

        if r_vcissuing.status_code != REQUEST_RESPONSE_200_OK:
            raise JsonVariables.Exceptions.VCIssueResponseFailed

        response_address = r_vcissuing.json().get('access').get('address')
        response_sessionToken = r_vcissuing.json().get('payload')        
        response_bindingMethod = r_vcissuing.json().get('access').get('binding')

        if not re.compile(JsonVariables.Regex.REGEX_ADDRESS).match(response_address):
            raise JsonVariables.Exceptions.ErrorAddressDoesntFitRegex

        if not re.compile(JsonVariables.Regex.REGEX_MSTOKEN).match(response_sessionToken):
            raise JsonVariables.Exceptions.ErrorTokenDoesntFitRegex

        if response_bindingMethod not in ['HTTP-POST-REDIRECT', 'HTTP-GET-REDIRECT']: #GET is added temporarly for alignemenmt with dashboard
            raise JsonVariables.Exceptions.ErrorBindingDoesntFitList

        #Addaptation of the response address to the specific moduleID endpoint 
        response_address = response_address + '/' + VCDefinition

        return JsonResponse(JsonConstructor(_address=response_address, _msToken=response_sessionToken, _bindingMethod=response_bindingMethod), status=200)

    except JsonVariables.Exceptions.MethodNotValid:
            print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_METHOD_MUST_BE_POST)
            return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_METHOD_MUST_BE_POST), status=405)


    except JsonVariables.Exceptions.RequestNeedsUUID:
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_UUID), status=400)


    except JsonVariables.Exceptions.ErrorInvalidLengthSessionId:
        # Tracing details error only on the server 
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_INVALID_LENGTH_SESSIONID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=502)

    except JsonVariables.Exceptions.RequestWithInvalidUUID:
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_UUID), status=400)


    except JsonVariables.Exceptions.RequestWithOutdatedUUID:
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_OUTDATED_UUID), status=401)


    except JsonVariables.Exceptions.RequestNeedsModuleID:
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITHOUT_MODULEID), status=400)


    except JsonVariables.Exceptions.RequestWithInvalidModuleID:
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_REQUEST_WITH_INVALID_MODULEID), status=400)


    except JsonVariables.Exceptions.CallbackResponseFailed:
        # Tracing details error only on the server 
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_CALLBACK_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=502)


    except JsonVariables.Exceptions.ListResponseFailed:
        # Tracing details error only on the server 
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_LIST_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=502)

    except JsonVariables.Exceptions.NoModuleIDinVCDefinitionsList:
        # Tracing details error only on the server 
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_MODULEID_NOT_IN_VCDEFINITIONS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=502)

    except JsonVariables.Exceptions.IdentitiesCantBeRetrieved:
        # Tracing details error only on the server 
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_IDENTITIES_RETRIEVAL_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=401)


    except JsonVariables.Exceptions.VCIssueResponseFailed:
        # Tracing details error only on the server 
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_VC_ISSUE_RESPONSE_HAS_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorTokenDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_TOKEN_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorAddressDoesntFitRegex:
        # Tracing details error only on the server 
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_ADDRESS_DOESNT_FIT_REGEX)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=502)


    except JsonVariables.Exceptions.ErrorBindingDoesntFitList:
        # Tracing details error only on the server 
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_BINDING_DOESNT_FIT_LIST)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=502)

    except:
        print(API_VC_ISSUE_DEBUG_CODE + JsonVariables.Error.ERROR_VC_ISSUE_FAILED)
        return JsonResponse(JsonConstructor(_ERROR=JsonVariables.Error.ERROR_VC_ISSUE_FAILED), status=500)

"""
    UC0.01

    CUSTOM USERCASE associated to cl/ident/mgr/list:

    It retrieves the storeEntry Set for the identiies loaded in the session (at the SM) without the linked ones.

"""
def uc0_01(request):

    def managerList(_UUID):
        error_text = 'An error has been occured with the API Calls. Please, contact the System Administrador (Error_code: _ML01)'

        try:
            assert(sessionExists(_UUID))
            assert(sessionValid(_UUID))
        except:
            if (Settings.DEBUG): print('DEBUG-uc0_01-ML-001: Error assert session exists or valid')
            return error_text, 401


        cl_ident = Cl_ident()
        user_session = getSessionId(_UUID)
        
        identities = cl_ident.jsonParser(cl_ident.mgrList(user_session.sessionID))

        #dict( {"uniqueProviders": list(set(providers_list)), "identitiesList": identities_list} )

        if('linkedID' in identities['uniqueProviders']):
            if (Settings.DEBUG): print('There are linked identities in the dict.') #TO-DO: Delete.

            #Remove Provider == 'linkedID'
            identities['uniqueProviders'].remove('linkedID')
            #Remove dictionaries that contents the ('provider': 'linkedID') Key-Value inside.
            identities['identitiesList'] = [identity for identity in identities['identitiesList'] if not (identity['provider'] == 'linkedID')]

        if('derivedID' in identities['uniqueProviders']):
            if (Settings.DEBUG): print('There are derived identities in the dict.') #TO-DO: Delete.

            #Remove Provider == 'derivedID'
            identities['uniqueProviders'].remove('derivedID')
            #Remove dictionaries that contents the ('provider': 'derivedID') Key-Value inside.
            identities['identitiesList'] = [identity for identity in identities['identitiesList'] if not (identity['provider'] == 'derivedID')]


        return '{}'.format(json.dumps(identities)), 200

    try:
        parametro_http_UUID = request.GET['data']
    except:
        return HttpResponse('Data not found in the request', status=404)

    if (len(parametro_http_UUID) == 32):
        response_text, status_code = managerList(parametro_http_UUID)
        return HttpResponse(response_text, status=status_code)
    else:
        if (Settings.DEBUG): print('DEBUG-uc0_01-ML-002: Error invalid UUID = {}'.format(parametro_http_UUID))
        return HttpResponse('Invalid data', status=404)


"""
    UC0.02

    CUSTOM USERCASE associated to cl/ident/mgr/list:

    It retrieves the storeEntry Set for all identiies loaded in the session (at the SM).

"""
def uc0_02(UUID):

    def managerList(_UUID):
        error_text = 'An error has been occured with the API Calls. Please, contact the System Administrador (Error_code: _ML02)'

        try:
            assert(sessionExists(_UUID))
            assert(sessionValid(_UUID))
        except:
            if (Settings.DEBUG): print('DEBUG-uc0_02-ML-001: Error assert session exists or valid')
            return None


        cl_ident = Cl_ident()
        user_session = getSessionId(_UUID)
        
        identities = cl_ident.jsonParser(cl_ident.mgrList(user_session.sessionID))

        return identities

    try:
        assert(len(UUID) == 32)

        return managerList(UUID)

    except:
        if (Settings.DEBUG): print('DEBUG-uc0_02-ML-002: Error invalid UUID = {}'.format(UUID))
        return None
