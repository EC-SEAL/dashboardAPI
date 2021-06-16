""" Json Variables """

class Dataset():

    #{% verbatim %}

    dataset = '''{{
                    "id": "{id}", "attributes": [
                        {{  "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#DocumentCode",
                            "friendlyName"	:"DocumentCode",
                            "encoding"		: "UTF-8",
                            "mandatory"	    : "true",
                            "values"		: ["{DocumentCode_value}"]

                        }},
                        {{
                            "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#IssuingState",
                            "friendlyName"	:"IssuingState", 
                            "encoding"		: "UTF-8", 
                            "mandatory"	    : "true",
                            "values"		: ["{IssuingState_value}"]

                        }},
                        {{
                            "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#DocumentNumber",
                            "friendlyName"	:"DocumentNumber", 
                            "encoding"		: "UTF-8", 
                            "mandatory"	    : "true",
                            "values"		: ["{DocumentNumber_value}"]

                        }},
                        {{
                            "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#DateOfExpiry",
                            "friendlyName"	:"DateOfExpiry", 
                            "encoding"		: "UTF-8", 
                            "mandatory"	    : "true",
                            "values"		: ["{DateOfExpiry_value}"]

                        }},
                        {{
                            "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#GivenName",
                            "friendlyName"	:"GivenName", 
                            "encoding"		: "UTF-8", 
                            "mandatory"	    : "true",
                            "values"		: ["{GivenName_value}"]

                        }},
                        {{
                            "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#Surname",
                            "friendlyName"	:"Surname", 
                            "encoding"		: "UTF-8", 
                            "mandatory"	    : "true",
                            "values"		: ["{Surname_value}"]

                        }},
                        {{
                            "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#Nationality",
                            "friendlyName"	:"Nationality", 
                            "encoding"		: "UTF-8", 
                            "mandatory"	    : "true",
                            "values"		: ["{Nationality_value}"]

                        }},
                        {{
                            "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#DateOfBirth",
                            "friendlyName"	:"DateOfBirth", 
                            "encoding"		: "UTF-8", 
                            "mandatory"	    : "true",
                            "values"		: ["{DateOfBirth_value}"]

                        }},
                        {{
                            "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#Sex",
                            "friendlyName"	:"Sex", 
                            "encoding"		: "UTF-8", 
                            "mandatory"	    : "true",
                            "values"		: ["{Sex_value}"]

                        }},
                        {{
                            "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#PlaceOfBirth",
                            "friendlyName"	:"PlaceOfBirth", 
                            "encoding"		: "UTF-8", 
                            "mandatory"	    : "true",
                            "values"		: ["{PlaceOfBirth_value}"]

                        }}
                    ],
                    "subjectId": "DocumentNumber",
                    "issuerId": "IssuingState",
                    "type": "eMRTD",
                    "issued": "{issued}"
                }}'''

                        # {{
                        #     "name" : "https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf#FaceImage",
                        #     "friendlyName"	:"FaceImage", 
                        #     "encoding"		: "Binary", 
                        #     "mandatory"	    : "true",
                        #     "values"		: null
                        # }}                

    signed_dataset = '{{"dataSetSerialised": "{datasetSerialised_value}", "signature": "{signature_value}"}}'

    #{% endverbatim %}


class Response():

    # Response Base
    # response_base = """{
    #                     "description": {response_description},
    #                     "content": {
    #                         "application/json": {
    #                             {response_elements}
    #                     }

    #                 }"""
    
    #{% verbatim %}
    
    response_base = '{{ "description": "{response_description}","content": {{"application/json": {{ {response_elements} }} }} }}'                  

    # Response elements 
    # element_string = """
    #                     "{element_name}":{
    #                         "schema": {
    #                             "type": "string",
    #                             "value": {response_value}
    #                         }
    #                     }"""

    #element_string = '"{element_name}":{{"schema": {{"type": "string","value": "{response_value}" }} }}'
    element_string = '"{element_name}":{{"schema": {{"type": "string","value": {response_value} }} }}'
    
    #{% endverbatim %}


# Class for REGEX
class Regex():

    REGEX_MSTOKEN = r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$'

    REGEX_ADDRESS = r'^((http|https):\/\/)(([a-zA-Z0-9-]{2,256}.)?([a-zA-Z0-9-]{2,256}.[a-z]{2,6}))(:[0-9]{2,5})?([a-zA-Z-\/]{2,256})?$'


# JsonConstructor ERROR VARIABLES:
class Error():

    NO_ERROR = False

    ERROR_METHOD_MUST_BE_POST = 'The method must be POST'
    ERROR_METHOD_MUST_BE_GET = 'The method must be GET'

    ERROR_SESSION_NOT_CREATED = 'The session has not been created'
    ERROR_RETRIEVE_IDENTITY_FAILED = 'The identity retrieving process has failed'
    ERROR_DERIVE_IDENTITY_FAILED = 'The identity derivation process has failed'
    ERROR_PERSISTENCE_LOAD_FAILED = 'The datastore load process has failed'
    ERROR_PERSISTENCE_STORE_FAILED = 'The datastore store process has failed'
    ERROR_SSI_LINK_FAILED = 'The SSI link process has failed'
    ERROR_VC_ISSUE_FAILED = 'The VC issue process has failed'
    ERROR_LIST_FAILED = 'The list process has failed'
    ERROR_MODULEID_NOT_IN_VCDEFINITIONS_FAILED = 'The moduleID is not in the VCDefinitions list'
    ERROR_IDENTITIES_RETRIEVAL_FAILED = 'The identities retrieval process has failed'
    ERROR_MSTOKEN_VALIDATION_FAILED = 'The msToken validation process has failed'
    ERROR_ID_ALL_LIST_FAILED = 'The identities list retrieval process has failed'
    ERROR_ID_EMRTD_FAILED = 'The eMRTD identity load process has failed'

    ERROR_GENERATING_UUID = 'The UUID generation has failed'    
    ERROR_INVALID_LENGTH_SESSIONID = 'The sessionId length is invalid'

    ERROR_REQUEST_WITHOUT_UUID = 'The request needs to be sent together with an UUID'
    ERROR_REQUEST_WITH_INVALID_UUID = 'The UUID received is invalid'
    ERROR_REQUEST_WITH_OUTDATED_UUID = 'The UUID received is outdated'

    ERROR_REQUEST_WITHOUT_DATASET = 'The request needs to be sent together with an Identity DataSet'

    ERROR_REQUEST_WITHOUT_MODULEID = 'The request needs to be sent together with a moduleID'
    ERROR_REQUEST_WITH_INVALID_MODULEID =  'The moduleID received is invalid'

    ERROR_REQUEST_WITHOUT_MSTOKEN = 'The request needs to be sent together with an msToken'

    ERROR_REQUEST_WITHOUT_IDENTITY_ID = 'The request needs to be sent together with the identities IDs'

    ERROR_ID_LIST_EMPTY = 'The request had produced an empty identities dictionary'
    ERROR_CANT_RETRIEVE_ID = 'The request identities could not be retrieved'

    ERROR_CALLBACK_RESPONSE_HAS_FAILED = 'The callback response has failed'
    ERROR_AUTH_RESPONSE_HAS_FAILED = 'The authentication response has failed'
    ERROR_IDENT_RESPONSE_HAS_FAILED = 'The identification response has failed'
    ERROR_IDENT_RESPONSE_UNAUTHORIZED = 'The identification response has been unauthorized'
    ERROR_PERSISTENCE_RESPONSE_HAS_FAILED = 'The persistence response has failed'
    ERROR_VC_ISSUE_RESPONSE_HAS_FAILED = 'The VC issue response has failed'
    ERROR_TOKEN_RESPONSE_HAS_FAILED = 'The token response has failed'

    ERROR_TOKEN_DOESNT_FIT_REGEX = 'The token does not fit the regex expression'
    ERROR_ADDRESS_DOESNT_FIT_REGEX = 'The address does not fit the regex expression'
    ERROR_BINDING_DOESNT_FIT_LIST = 'The binding method has not been found on the binding list'


# Class for exceptions handling
class Exceptions():

    class MethodNotValid(Exception): 
        # Class exception for handling methods not permitted
        pass


    class ErrorGeneratingUUID(Exception):
        # Class exception for handling UUID generation error
        pass


    class ErrorInvalidLengthSessionId(Exception):
        # Class exception for handling length sessionID error
        pass

    
    class ErrorTokenDoesntFitRegex(Exception):
        # Class exception for handling error in token formating regex matching
        pass

    class ErrorAddressDoesntFitRegex(Exception):
        # Class exception for handling error in address formating regex matching
        pass

    class ErrorBindingDoesntFitList(Exception):
        # Class exception for handling error matching binding method in list
        pass

    # Request handling errors 

    class RequestNeedsUUID(Exception):
        # Class exception for handling requests without mandatory UUID
        pass

    class RequestNeedsDataSet(Exception):
        # Class exception for handling requests without mandatory DataSet
        pass

    class RequestWithInvalidUUID(Exception):
        # Class exception for handling requests with invalid UUID
        pass


    class RequestWithOutdatedUUID(Exception):
        # Class exception for handling requests with outdated UUID
        pass


    class RequestNeedsModuleID(Exception):
        # Class exception for handling requests without mandatory ModuleID
        pass


    class RequestWithInvalidModuleID(Exception):
        # Class exception for handling requests with invalid ModuleID
        pass


    class CallbackResponseFailed(Exception):
        # Class exception for handling Callback requests with failed response
        pass
    
    
    class AuthResponseFailed(Exception):
        # Class exception for handling Authentication requests with failed response
        pass

    class IdentResponseFailed(Exception):
        # Class exception for handling Ident requests with failed response
        pass

    class IdentResponseUnauthorized(Exception):
        # Class exception for handling Ident requests with unauthorized response
        pass

    class PersistenceResponseFailed(Exception):
        # Class exception for handling Persistence requests with failed response
        pass

    class SSILinkResponseFailed(Exception):
        # Class exception for handling SSI requests with failed response
        pass

    class VCIssueResponseFailed(Exception):
        # Class exception for handling VC issue requests with failed response
        pass

    class ListResponseFailed(Exception):
        # Class exception for handling list requests with failed response
        pass

    class NoModuleIDinVCDefinitionsList(Exception):
        # Class exception for handling list requests with failed response
        pass

    class IdentitiesCantBeRetrieved(Exception):
        # Class exception for handling Identities retrievals with failed fetching
        pass

    class RequestNeedsmsToken(Exception):
        # Class exception for handling requests without mandatory msToken
        pass

    class TokenResponseFailed(Exception):
        # Class exception for handling msToken request with failed response
        pass

    class RequestNeedsIdentityID(Exception):
        # Class exception for handling requests without mandatory identity ID(s)
        pass

    class IdentitiesListEmpty(Exception):
        # Class exception for handling requests that produces empty identities dictionary
        pass

    class CantRetrieveRequestedIdentities(Exception):
        # Class exception for handling request that produces not retrievable identities dictionary
        pass