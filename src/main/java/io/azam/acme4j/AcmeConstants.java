package io.azam.acme4j;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class AcmeConstants {
	public static final String UTF8 = "UTF-8";
	public static final String UTF8_UNSUPPORTED = "Current JRE does not support UTF-8";
	public static final String HTTP01 = "http-01";
	public static final String DNS01 = "dns-01";
	public static final String HEADER = "header";
	public static final String PAYLOAD = "payload";
	public static final String PROTECTED = "protected";
	public static final String SIGNATURE = "signature";
	public static final String NONCE = "nonce";
	public static final String ALG = "alg";
	public static final String JWK = "jwk";
	public static final String E = "e";
	public static final String KTY = "kty";
	public static final String N = "n";
	public static final String RSA = "RSA";
	public static final String RS256 = "RS256";
	public static final String RESOURCE = "resource";
	public static final String CONTACT = "contact";
	public static final String NEWREG = "new-reg";
	public static final String AGREEMENT = "agreement";
	public static final String NEWAUTHZ = "new-authz";
	public static final String IDENTIFIER = "identifier";
	public static final String TYPE = "type";
	public static final String DNS = "dns";
	public static final String VALUE = "value";
	public static final String CHALLENGE = "challenge";
	public static final String CHALLENGES = "challenges";
	public static final String URI = "uri";
	public static final String TOKEN = "token";
	public static final String KEYAUTHORIZATION = "keyAuthorization";
	public static final String STATUS = "status";
	public static final String PENDING = "pending";
	public static final String VALID = "valid";
	public static final String NEWCERT = "new-cert";
	public static final String CSR = "csr";
	public static final String CONTENTTYPE = "Content-Type";
	public static final String APPLICATIONJSON = "application/json";
	public static final String REPLAYNONCE = "Replay-Nonce";
	public static final String SHA256 = "SHA-256";
	public static final String SHA256WITHRSA = "SHA256withRSA";
	public static final String ALGORITHM_UNSUPPORTED = "Current JRE does not support this algorithm";
	public static final String FRAG_DIRECTORY = "/directory";
	public static final String FRAG_NEWREG = "/acme/new-reg";
	public static final String FRAG_NEWAUTHZ = "/acme/new-authz";
	public static final String FRAG_NEWCERT = "/acme/new-cert";
	public static final String FRAG_REVOKECERT = "/acme/revoke-cert";
	public static final Set<Integer> REGISTERED_STATUSCODES = new HashSet<Integer>(
			Arrays.asList(200, 201, 409));
}
