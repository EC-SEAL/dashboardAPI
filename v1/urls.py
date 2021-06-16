from django.urls import include, path
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
    path('identity/link', csrf_exempt(useCases.api_identityLink)), #POST
    path('identity/all/list', csrf_exempt(useCases.api_identityAllList)), #POST

    path('identity/<str:moduleID>/load', csrf_exempt(useCases.api_eMRTD)), # POST
    
    # path('session/end', csrf_exempt(useCases.sessionEnd)), 
]