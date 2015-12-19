package io.azam.acme4j;

import static io.azam.acme4j.AcmeConstants.UTF8;
import static io.azam.acme4j.AcmeConstants.UTF8_UNSUPPORTED;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AcmeUtil {
	public static String toBase64(String s) {
		try {
			// return Base64.encodeBase64URLSafeString(s.getBytes(UTF8));
			return javax.xml.bind.DatatypeConverter.printBase64Binary(
					s.getBytes(UTF8)).replaceAll("=", "");
		} catch (UnsupportedEncodingException e) {
			// We should not get here
			throw new UnsupportedOperationException(UTF8_UNSUPPORTED);
		}
	}

	public static String toBase64(byte[] b) {
		return javax.xml.bind.DatatypeConverter.printBase64Binary(b)
				.replaceAll("=", "");
	}

	public static String fromBase64(String s) {
		try {
			return new String(
					javax.xml.bind.DatatypeConverter.parseBase64Binary(s), UTF8);
		} catch (UnsupportedEncodingException e) {
			// We should not get here
			throw new UnsupportedOperationException(UTF8_UNSUPPORTED);
		}
	}

	public static String toJson(Map<String, Object> map)
			throws JsonProcessingException {
		return new ObjectMapper().writeValueAsString(map);
	}

	@SuppressWarnings("unchecked")
	public static Map<String, Object> fromJson(String json) throws IOException {
		return new ObjectMapper().readValue(json, Map.class);
	}

	private static synchronized void loadProvider() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static Object readPem(File file) throws IOException {
		loadProvider();
		BufferedReader r = null;
		PEMParser p = null;
		try {
			r = new BufferedReader(new FileReader(file));
			p = new PEMParser(r);
			return p.readObject();
		} finally {
			if (p != null) {
				try {
					p.close();
				} catch (IOException e) {
				}
			}
			if (r != null) {
				try {
					r.close();
				} catch (IOException e) {
				}
			}
		}
	}

	public static KeyPair readKeyFile(File file) throws IOException {
		Object o = readPem(file);
		if (o != null && o instanceof PEMKeyPair) {
			return new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) o);
		}
		return null;
	}

	public static PKCS10CertificationRequest readCsrFile(File file)
			throws IOException {
		Object o = readPem(file);
		if (o != null && o instanceof PKCS10CertificationRequest) {
			return (PKCS10CertificationRequest) o;
		}
		return null;
	}

	public static Certificate readCert(File file) throws IOException,
			CertificateException {
		Object o = readPem(file);
		if (o != null && o instanceof X509CertificateHolder) {
			return new JcaX509CertificateConverter()
					.getCertificate((X509CertificateHolder) o);
		}
		return null;
	}

	public static Set<String> getSubjectAltNames(PKCS10CertificationRequest csr) {
		Set<String> s = new HashSet<String>();
		for (Attribute attr : csr.getAttributes()) {
			System.out.println(attr.getAttrType());
			// 1.2.840.113549.1.9.14
			if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr
					.getAttrType())) {
				for (ASN1Encodable asn1 : attr.getAttributeValues()) {
					System.out.println(Extensions.getInstance(asn1)
							.getExtensionOIDs());
					Extensions exts = Extensions.getInstance(asn1);
					GeneralNames gns = GeneralNames.fromExtensions(exts,
							Extension.subjectAlternativeName); // 2.5.29.17
					for (GeneralName gn : gns.getNames()) {
						if (GeneralName.dNSName == gn.getTagNo()) {
							s.add(gn.getName().toString());
						}
						if (GeneralName.iPAddress == gn.getTagNo()) {
							// FIXME: ip address is encoded
						}
					}
				}
			}
		}
		return s;
	}
}
