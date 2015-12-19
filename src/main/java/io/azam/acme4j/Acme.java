package io.azam.acme4j;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class Acme {
	public static final String ACTION_HELP = "help";
	public static final String ACTION_REGISTER = "register";
	public static final String ACTION_CHALLENGE = "challenge";
	public static final String ACTION_VERIFY = "verify";
	public static final String ACTION_CERTIFICATE = "cert";
	public static final Set<String> ACTIONS = new HashSet<String>(
			Arrays.asList(ACTION_HELP, ACTION_REGISTER, ACTION_CHALLENGE,
					ACTION_VERIFY, ACTION_CERTIFICATE));

	public static void main(String[] args) {
		Options o = new Options();
		o.addOption(Option.builder("e").longOpt("endpoint").hasArg().required()
				.desc("Endpoint URL").type(URI.class).build());
		o.addOption(Option.builder("c").longOpt("contact").hasArg().required()
				.desc("Contact (mailto:me@example.com)").type(String.class)
				.build());
		o.addOption(Option.builder("a").longOpt("agreement").hasArg()
				.required().desc("Agreement").type(String.class).build());
		o.addOption(Option.builder("k").longOpt("key").hasArg().required()
				.desc("Account Key File").type(File.class).build());
		o.addOption(Option.builder("r").longOpt("csr").hasArg().required()
				.desc("Certificate Signing Request File").type(File.class)
				.build());
		o.addOption(Option.builder("ca").longOpt("ca").hasArgs()
				.desc("Trusted Certificate Authority Certificate(s)")
				.type(File.class).build());
		if (args.length > 0 && ACTIONS.contains(args[0])
				&& !ACTION_HELP.equals(args[0])) {
			String[] os = new String[(args.length > 0) ? args.length - 1 : 0];
			System.arraycopy(args, 1, os, 0, args.length - 1);
			try {
				CommandLineParser p = new DefaultParser();
				CommandLine cl = p.parse(o, os);
				String contact = cl.getOptionValue("contact");
				String agreement = cl.getOptionValue("agreement");
				URI ep = new URI(cl.getOptionValue("endpoint"));
				KeyPair key = AcmeUtil.readKeyFile(new File(cl
						.getOptionValue("key"), "r"));
				PKCS10CertificationRequest csr = AcmeUtil.readCsrFile(new File(
						cl.getOptionValue("csr"), "r"));
				Certificate[] certs = null;
				if (cl.hasOption("ca")) {
					String[] caPaths = cl.getOptionValues("ca");
					if (caPaths != null && caPaths.length > 0) {
						for (String caPath : caPaths) {
							if (caPath != null && !caPath.isEmpty()) {
								Certificate ca = AcmeUtil.readCert(new File(
										caPath));
								if (ca != null) {
									if (certs == null) {
										certs = new Certificate[1];
									} else {
										Certificate[] tmpCerts = new Certificate[certs.length + 1];
										System.arraycopy(certs, 0, tmpCerts, 0,
												certs.length);
										certs = tmpCerts;
									}
									certs[certs.length - 1] = ca;
								}
							}
						}
					}
				}
				AcmeClient c = new AcmeClient(ep, contact, key, csr, agreement,
						certs);
				if (ACTION_REGISTER.equals(args[0])) {
					c.newReg();
				} else if (ACTION_CHALLENGE.equals(args[0])) {
					c.newAuthz();
				} else if (ACTION_VERIFY.equals(args[0])) {
					c.status(null);
				} else if (ACTION_CERTIFICATE.equals(args[0])) {
					c.newCert();
				}
				System.exit(0);
				return;
			} catch (ParseException e) {
				System.out.println("Invalid arguments: " + e.getMessage());
				HelpFormatter hf = new HelpFormatter();
				hf.printHelp("{help|register|challenge|cert|verify}", o, true);
			} catch (IOException e) {
				e.printStackTrace();
			} catch (URISyntaxException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}
			System.exit(1);
			return;
		}
		HelpFormatter hf = new HelpFormatter();
		hf.printHelp("{help|register|challenge|cert|verify}", o, true);
		System.exit(0);
		return;
	}
}
