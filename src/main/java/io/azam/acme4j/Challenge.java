package io.azam.acme4j;

public class Challenge {
	public final String domain;
	public final String uri;
	public final String type;
	public final String token;
	public final String keyAuthorization;

	public Challenge(String domain, String uri, String type, String token,
			String keyAuthorization) {
		this.domain = domain;
		this.uri = uri;
		this.type = type;
		this.token = token;
		this.keyAuthorization = keyAuthorization;
	}
}
