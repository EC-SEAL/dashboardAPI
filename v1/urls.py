

from django.urls import include, path, re_path
from django.views.decorators.csrf import csrf_exempt

from .src import useCases
from .src import controlFunctions

urlpatterns = [

    # Test path
    path('test', csrf_exempt(useCases.api_test)),   # GET

    # Index resources
    path('', csrf_exempt(useCases.api_help)), #GET #OpenAPI Object
    path('help', csrf_exempt(useCases.api_help)), #GET

    # Token Validate
    path('token/validate', csrf_exempt(useCases.api_tokenValidate)), #POST

    # Session resources
    path('session/start', csrf_exempt(useCases.api_sessionStart)), # POST

    # PDS
    path('datastore/<str:moduleID>/load', csrf_exempt(useCases.api_datastoreLoad)),  # POST
    path('datastore/<str:moduleID>/store', csrf_exempt(useCases.api_datastoreStore)),  # POST
    
    # SSI
    path('decentralized/authenticate', csrf_exempt(useCases.api_ssiLink)),  # POST
    path('decentralized/vc/issue', csrf_exempt(useCases.api_vcIssue)), #POST

    # Identity resources
    path('identity/retrieve', csrf_exempt(useCases.api_retrieveIdData)), # POST
    path('identity/derive', csrf_exempt(useCases.api_deriveIdentifier)), #POST
    path('identity/all/list', csrf_exempt(useCases.api_identityAllList)), #POST


    
    # path('session/end', csrf_exempt(useCases.sessionEnd)), 
  
    


    # path('', views.index, name='index'),

    # re_path(r'^tokenFlag=(?P<UUID>[a-z0-9]{32})$', csrf_exempt(controlFunctions.tokenFlag)),
    # re_path(r'^identitymanager/tokenFlag=(?P<UUID>[a-z0-9]{32})$', csrf_exempt(controlFunctions.tokenFlag)),
    # re_path(r'^tokenValidate=(?P<UUID>[a-z0-9]{32})$', csrf_exempt(controlFunctions.tokenControl)),

    # path('loadLocalPDS/', csrf_exempt(useCases.uc1_02)),
    # path('loadCloudPDS/', csrf_exempt(useCases.uc1_03)),
    # path('SSI/', csrf_exempt(useCases.uc1_04)),
    
    # path('identitymanager/', views.identity_manager, name='identity_manager'),

    # path('identitymanager/storeLocalPDS/', csrf_exempt(useCases.uc2_02)),
    # path('identitymanager/storeCloudPDS/', csrf_exempt(useCases.uc2_05)),

    # path('identitymanager/addID/', csrf_exempt(useCases.uc3_02)),

    # path('identitymanager/vcIssue/', csrf_exempt(useCases.uc5_01)),

    # path('identitymanager/idDeriv/', csrf_exempt(useCases.uc6_01)),

    # path('identitymanager/idRecon/', csrf_exempt(useCases.uc7_01)),
    # path('identitymanager/idSelec/', csrf_exempt(useCases.uc0_01)),

    # re_path(r'^identitymanager/manageidentitydata=(?P<UUID>[a-z0-9]{32})$', views.manageidentity, name='manageidentity'),

    # re_path(r'^testGetSessionId=(?P<UUID>[a-z0-9]{32})$', csrf_exempt(controlFunctions.debugGetSessionId)),
]