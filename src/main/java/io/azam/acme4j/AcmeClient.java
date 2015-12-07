package io.azam.acme4j;

import static io.azam.acme4j.AcmeConstants.AGREEMENT;
import static io.azam.acme4j.AcmeConstants.ALG;
import static io.azam.acme4j.AcmeConstants.ALGORITHM_UNSUPPORTED;
import static io.azam.acme4j.AcmeConstants.APPLICATIONJSON;
import static io.azam.acme4j.AcmeConstants.CHALLENGE;
import static io.azam.acme4j.AcmeConstants.CHALLENGES;
import static io.azam.acme4j.AcmeConstants.CONTACT;
import static io.azam.acme4j.AcmeConstants.CONTENTTYPE;
import static io.azam.acme4j.AcmeConstants.CSR;
import static io.azam.acme4j.AcmeConstants.DNS;
import static io.azam.acme4j.AcmeConstants.E;
import static io.azam.acme4j.AcmeConstants.FRAG_DIRECTORY;
import static io.azam.acme4j.AcmeConstants.FRAG_NEWAUTHZ;
import static io.azam.acme4j.AcmeConstants.FRAG_NEWCERT;
import static io.azam.acme4j.AcmeConstants.FRAG_NEWREG;
import static io.azam.acme4j.AcmeConstants.HEADER;
import static io.azam.acme4j.AcmeConstants.IDENTIFIER;
import static io.azam.acme4j.AcmeConstants.JWK;
import static io.azam.acme4j.AcmeConstants.KEYAUTHORIZATION;
import static io.azam.acme4j.AcmeConstants.KTY;
import static io.azam.acme4j.AcmeConstants.N;
import static io.azam.acme4j.AcmeConstants.NEWAUTHZ;
import static io.azam.acme4j.AcmeConstants.NEWCERT;
import static io.azam.acme4j.AcmeConstants.NEWREG;
import static io.azam.acme4j.AcmeConstants.NONCE;
import static io.azam.acme4j.AcmeConstants.PAYLOAD;
import static io.azam.acme4j.AcmeConstants.PROTECTED;
import static io.azam.acme4j.AcmeConstants.REGISTERED_STATUSCODES;
import static io.azam.acme4j.AcmeConstants.REPLAYNONCE;
import static io.azam.acme4j.AcmeConstants.RESOURCE;
import static io.azam.acme4j.AcmeConstants.RS256;
import static io.azam.acme4j.AcmeConstants.RSA;
import static io.azam.acme4j.AcmeConstants.SHA256;
import static io.azam.acme4j.AcmeConstants.SHA256WITHRSA;
import static io.azam.acme4j.AcmeConstants.SIGNATURE;
import static io.azam.acme4j.AcmeConstants.STATUS;
import static io.azam.acme4j.AcmeConstants.TOKEN;
import static io.azam.acme4j.AcmeConstants.TYPE;
import static io.azam.acme4j.AcmeConstants.URI;
import static io.azam.acme4j.AcmeConstants.UTF8;
import static io.azam.acme4j.AcmeConstants.UTF8_UNSUPPORTED;
import static io.azam.acme4j.AcmeConstants.VALUE;
import static io.azam.acme4j.AcmeUtil.fromJson;
import static io.azam.acme4j.AcmeUtil.getSubjectAltNames;
import static io.azam.acme4j.AcmeUtil.toBase64;
import static io.azam.acme4j.AcmeUtil.toJson;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.fasterxml.jackson.core.JsonProcessingException;

public class AcmeClient {
	private URI endpoint;
	private String contact;
	private KeyPair key;
	private PKCS10CertificationRequest csr;
	private String agreement;
	private Map<String, Object> jwk;
	private String thumbprint;

	public AcmeClient(URI endpoint, String contact, KeyPair key,
			PKCS10CertificationRequest csr, String agreement) {
		if (endpoint == null || contact == null || key == null || csr == null
				|| agreement == null) {
			throw new InvalidParameterException();
		}
		this.endpoint = endpoint;
		this.contact = contact;
		this.key = key;
		this.csr = csr;
		this.agreement = agreement;
		Map<String, Object> m = new TreeMap<String, Object>();
		m.put(KTY, RSA);
		m.put(E, toBase64(((RSAPublicKey) this.key.getPublic())
				.getPublicExponent().toByteArray()));
		m.put(N, toBase64(((RSAPublicKey) this.key.getPublic()).getModulus()
				.toByteArray()));
		this.jwk = Collections.unmodifiableMap(m);
		this.thumbprint = thumbprint();
	}

	private String sign(String encodedHeader, String encodedPayload)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		Signature s = Signature.getInstance(SHA256WITHRSA);
		s.initSign(this.key.getPrivate());
		String m = new String(encodedHeader + "." + encodedPayload);
		try {
			s.update(m.getBytes(UTF8));
		} catch (UnsupportedEncodingException e) {
			// We should not get here
			throw new UnsupportedOperationException(UTF8_UNSUPPORTED);
		}
		return toBase64(s.sign());
	}

	private String nonce() throws ClientProtocolException, IOException {
		HttpHead req = new HttpHead(this.endpoint.toString() + FRAG_DIRECTORY);
		HttpResponse res = HttpClients.createDefault().execute(req);
		if (res != null) {
			Header h = res.getFirstHeader(REPLAYNONCE);
			if (h != null) {
				return h.getValue();
			}
		}
		return null;
	}

	private String thumbprint() {
		try {
			MessageDigest md = MessageDigest.getInstance(SHA256);
			md.update(toJson(this.jwk).getBytes(UTF8));
			return toBase64(md.digest());
		} catch (NoSuchAlgorithmException e) {
			// We should not get here
			throw new UnsupportedOperationException(ALGORITHM_UNSUPPORTED);
		} catch (UnsupportedEncodingException e) {
			// We should not get here
			throw new UnsupportedOperationException(UTF8_UNSUPPORTED);
		} catch (JsonProcessingException e) {
			// We should not get here
			return null;
		}
	}

	private Map<String, Object> header(String nonce) {
		Map<String, Object> m = new TreeMap<String, Object>();
		m.put(ALG, RS256);
		m.put(JWK, this.jwk);
		if (nonce != null && !nonce.isEmpty()) {
			m.put(NONCE, nonce);
		}
		return m;
	}

	private HttpResponse post(String uri, String payload)
			throws ClientProtocolException, IOException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		String nonce = nonce();
		HttpPost req = new HttpPost(uri);
		req.addHeader(CONTENTTYPE, APPLICATIONJSON);
		Map<String, Object> header = header(nonce);
		String encodedPayload = toBase64(payload);
		String encodedHeader = toBase64(toJson(header));
		Map<String, Object> p = new TreeMap<String, Object>();
		p.put(HEADER, header);
		p.put(PAYLOAD, encodedPayload);
		p.put(PROTECTED, encodedHeader);
		p.put(SIGNATURE, sign(encodedHeader, encodedPayload));
		req.setEntity(new StringEntity(toJson(p)));
		System.out.println(toJson(p));
		return HttpClients.createDefault().execute(req);
	}

	public boolean newReg() throws InvalidKeyException,
			ClientProtocolException, NoSuchAlgorithmException,
			SignatureException, JsonProcessingException, IOException {
		List<String> contacts = new ArrayList<String>(1);
		contacts.add(this.contact);
		Map<String, Object> payload = new TreeMap<String, Object>();
		payload.put(RESOURCE, NEWREG);
		payload.put(CONTACT, contacts);
		if (this.agreement != null) {
			payload.put(AGREEMENT, this.agreement);
		}
		HttpResponse res = post(this.endpoint.toString() + FRAG_NEWREG,
				toJson(payload));
		System.out.println(res.getStatusLine());
		return res != null
				&& res.getStatusLine() != null
				&& REGISTERED_STATUSCODES.contains(res.getStatusLine()
						.getStatusCode());
	}

	private List<Challenge> newAuthz(String domain) throws InvalidKeyException,
			ClientProtocolException, NoSuchAlgorithmException,
			SignatureException, JsonProcessingException, IOException {
		Map<String, Object> identifier = new TreeMap<String, Object>();
		identifier.put(TYPE, DNS);
		identifier.put(VALUE, domain);
		Map<String, Object> payload = new TreeMap<String, Object>();
		payload.put(RESOURCE, NEWAUTHZ);
		payload.put(IDENTIFIER, identifier);
		HttpResponse res = post(this.endpoint.toString() + FRAG_NEWAUTHZ,
				toJson(payload));
		if (res != null && res.getStatusLine() != null
				&& res.getStatusLine().getStatusCode() == 201) {
			HttpEntity entity = res.getEntity();
			if (entity != null) {
				String json = EntityUtils.toString(entity, UTF8);
				if (json != null) {
					List<Challenge> cl = new ArrayList<Challenge>();
					Map<String, Object> m = fromJson(json);
					if (m != null && m.containsKey(CHALLENGES)) {
						@SuppressWarnings("unchecked")
						List<Map<String, Object>> cml = (List<Map<String, Object>>) m
								.get(CHALLENGES);
						if (cml != null && cml instanceof List) {
							for (Map<String, Object> cm : cml) {
								if (cm != null) {
									Challenge c = new Challenge(domain,
											(String) cm.get(URI),
											(String) cm.get(TYPE),
											(String) cm.get(TOKEN),
											(String) cm.get(TOKEN) + "."
													+ this.thumbprint);
									cl.add(c);
								}
							}
						}
					}
					return cl;
				}
			}
		}
		return null;
	}

	public Map<String, List<Challenge>> newAuthz() throws InvalidKeyException,
			ClientProtocolException, NoSuchAlgorithmException,
			SignatureException, JsonProcessingException, IOException {
		if (newReg()) {
			Map<String, List<Challenge>> cm = new HashMap<String, List<Challenge>>();
			for (String d : getSubjectAltNames(this.csr)) {
				cm.put(d, newAuthz(d));
			}
			return cm;
		}
		return null;
	}

	public String status(Challenge challenge) throws InvalidKeyException,
			ClientProtocolException, NoSuchAlgorithmException,
			SignatureException, JsonProcessingException, IOException {
		Map<String, Object> m = new TreeMap<String, Object>();
		m.put(RESOURCE, CHALLENGE);
		m.put(KEYAUTHORIZATION, challenge.keyAuthorization);
		HttpResponse res = post(challenge.uri, toJson(m));
		if (res != null) {
			HttpEntity entity = res.getEntity();
			if (entity != null) {
				String json = EntityUtils.toString(entity, UTF8);
				if (json != null) {
					Map<String, Object> resMap = fromJson(json);
					if (resMap != null && resMap.containsKey(STATUS)) {
						return (String) resMap.get(STATUS);
					}
				}
			}
		}
		return null;
	}

	public byte[] newCert() throws InvalidKeyException,
			ClientProtocolException, NoSuchAlgorithmException,
			SignatureException, JsonProcessingException, IOException {
		Map<String, Object> m = new TreeMap<String, Object>();
		m.put(RESOURCE, NEWCERT);
		m.put(CSR, toBase64(""));
		HttpResponse res = post(this.endpoint.toString() + FRAG_NEWCERT,
				toJson(m));
		if (res != null && res.getStatusLine() != null
				&& res.getStatusLine().getStatusCode() == 201) {
			HttpEntity entity = res.getEntity();
			if (entity != null) {
				return EntityUtils.toByteArray(entity);
			}
		}
		return null;
	}

	public Map<String, String> directory() throws ClientProtocolException,
			IOException {
		HttpGet req = new HttpGet(this.endpoint.toString() + FRAG_DIRECTORY);
		req.addHeader(CONTENTTYPE, APPLICATIONJSON);
		HttpResponse res = HttpClients.createDefault().execute(req);
		if (res != null) {
			HttpEntity entity = res.getEntity();
			if (entity != null) {
				String json = EntityUtils.toString(entity, UTF8);
				if (json != null) {
					Map<String, Object> resMap = fromJson(json);
					if (resMap != null) {
						Map<String, String> ret = new TreeMap<String, String>();
						for (String k : resMap.keySet()) {
							Object v = resMap.get(k);
							if (v == null) {
								ret.put(k, null);
							} else if (v instanceof String) {
								ret.put(k, (String) v);
							} else {
								ret.put(k, v.toString());
							}
						}
						return ret;
					}
				}
			}
		}
		return null;
	}
}
