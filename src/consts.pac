# Taken from http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
enum exchange_type {
    IKE_SA_INIT = 34,
    IKE_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATIONAL = 37,
    IKE_SESSION_RESUME = 38
};

enum payload_type {
    # No further payloads
    NO_NEXT_PAYLOAD = 0,
    # Security Association
    SA = 33,
    # Key Exchange
    KE = 34,
    # Identification - Initiator
    ID_I = 35,
    # Identification - Responder
    ID_R = 36,
    # Certificate
    CERT = 37,
    # Certificate Request
    CERTREQ = 38,
    # Authentication
    AUTH = 39,
    # Nonce - Ni or Nr
    NONCE = 40,
    # Notify
    N = 41,
    # Delete
    D = 42,    
    # Vendor ID
    V = 43,
    # Traffic Selector - Initiator
    TS_I = 44,
    # Traffic Selector - Responder
    TS_R = 45,
    # Encrypted and Authenticated
    SK = 46,
    # Configuration
    CP = 47,
    # Extensible Authentication
    EAP = 48,
    # Generic Secure Password Method
    GSPM = 49,
    # Group Identification
    ID_G = 50,
    # Group Security Association
	GSA = 51,
    # Key Download
    KD = 52,
    # Encrypted and Authenticated Fragment
    SKF = 53,
    # Puzzle Solution
    PS = 54,
};
