package ca.uhn.fhir.jpa.demo;

import ca.uhn.fhir.model.primitive.IdDt;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRuleBuilderRuleOpClassifierFinished;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import org.codehaus.jackson.map.ObjectMapper;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.web.client.RestTemplate;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/*******************************************************************************
 * Copyright (c) 2018 Substance Abuse and Mental Health Services Administration (SAMHSA)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Eversolve, LLC
 *     Anthony Sute
 *******************************************************************************/

public class OAuthAuthorizationInterceptor extends AuthorizationInterceptor {

	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OAuthAuthorizationInterceptor.class);
	private static ObjectMapper mapper = new ObjectMapper();
	private static DefaultOAuth2AccessToken myAccessToken = null;
	private static RestTemplate restTemplate = null;
	private static String propertiesFile = FhirServerProperties.serverPropertiesFile;
	private static Properties properties = null;
	private static String oAuthHost = null;
	private static String ci = null;
	private static String cs = null;
	private static String pk = null;
	private static String iss = null;
	private static String aud = null;
	private static String ke = null;
	private static int allowedClockSkewInSeconds = 180;
	private static HttpsJwks httpsJkws = null;
	private static HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = null;
	private static JwtConsumer jwtConsumer = null;

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {

		if (properties == null) {
			try {
				properties = new Properties();
				properties.load(new FileInputStream(propertiesFile));
				OAuthAuthorizationInterceptor.oAuthHost = (properties.getProperty("OAuthHost") == null)
					? OAuthAuthorizationInterceptor.oAuthHost : properties.getProperty("OAuthHost");
				OAuthAuthorizationInterceptor.ci = (properties.getProperty("ci") == null)
					? OAuthAuthorizationInterceptor.ci : properties.getProperty("ci");
				OAuthAuthorizationInterceptor.cs = (properties.getProperty("cs") == null)
					? OAuthAuthorizationInterceptor.cs : properties.getProperty("cs");
				OAuthAuthorizationInterceptor.pk = (properties.getProperty("pk") == null)
					? OAuthAuthorizationInterceptor.pk : properties.getProperty("pk");
				OAuthAuthorizationInterceptor.iss = (properties.getProperty("iss") == null)
					? OAuthAuthorizationInterceptor.iss : properties.getProperty("iss");
				OAuthAuthorizationInterceptor.aud = (properties.getProperty("aud") == null)
					? OAuthAuthorizationInterceptor.aud : properties.getProperty("aud");
				OAuthAuthorizationInterceptor.ke = (properties.getProperty("ke") == null)
					? OAuthAuthorizationInterceptor.ke : properties.getProperty("ke");
				OAuthAuthorizationInterceptor.allowedClockSkewInSeconds = (properties.getProperty("AllowedClockSkewInSeconds") == null)
					? OAuthAuthorizationInterceptor.allowedClockSkewInSeconds : Integer.parseInt(properties.getProperty("AllowedClockSkewInSeconds"));
			} catch (IOException e) {
				throw new AuthenticationException(String.format("Error encountered loading JPAServer.properties file, %s, info=%s",
					propertiesFile,
					e.getMessage()),
					e);
			}
		}

		if ((ke == null) ||
			(ke.length() == 0))
		{
			logger.info("JSON public key endpoint parameter not specified in properties file, bypassing authorization");
			return new RuleBuilder()
				.allowAll()
				.build();
		}

		if (httpsJkws == null) {
			httpsJkws = new HttpsJwks(ke);
			httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);
			jwtConsumer = new JwtConsumerBuilder()
				.setRequireExpirationTime() // the JWT must have an expiration time
				.setAllowedClockSkewInSeconds(allowedClockSkewInSeconds) // allow configured leeway in validating time based claims to account for clock skew
				//.setRequireSubject() // the JWT must have a subject claim
				.setExpectedIssuer(((iss != null) && (iss.length() > 0)) ? true
						: false,
					((iss != null) && (iss.length() > 0)) ? iss
						: null) // whom the JWT needs to have been issued by
				.setExpectedAudience(((aud != null) && (aud.length() > 0)) ? true
						: false,
					((aud != null) && (aud.length() > 0)) ? aud
						: null) // to whom the JWT is intended for
				.setVerificationKeyResolver(httpsJwksKeyResolver)
				.build();
		}

		// Check if request has authorization header and Bearer token
		if (theRequestDetails.getHeader("Authorization") == null) {
			// Throw an HTTP 401
			throw new AuthenticationException("Missing Authorization header value");
		} else if (!theRequestDetails.getHeader("Authorization").toUpperCase().startsWith("BEARER ")) {
			logger.error("Bearer not found (do not log in production!) = " + theRequestDetails.getHeader("Authorization"));
			throw new AuthenticationException("Missing Bearer token in Authorization header (must start with 'Bearer')");
		}

		String authHeader = theRequestDetails.getHeader("Authorization");
		String encodedAccessToken = authHeader.split(" ")[1];

		logger.info("Authorization header (do not log in production!) = " + authHeader);
		logger.info("encodedAccessToken (do not log in production!) = " + encodedAccessToken);

		IdDt patientId = null;

		// Self validate JWT...
		JwtClaims claims = null;
		try {
			claims = checkAuthorization(encodedAccessToken);
		} catch (Exception e) {
			throw new AuthenticationException(String.format("Error parsing Bearer token, exception info=%s",
				e.getCause()),
				e);
		}

		if (claims.getClaimValue("patient") != null) {
			patientId = new IdDt(claims.getClaimValue("patient").toString());
		}

		if ((claims.getClaimValue("scope") != null) &&
			(!((ArrayList)claims.getClaimValue("scope")).isEmpty())) {
			// Iterate through the scopes and populate a RuleBuilder instance...
			RuleBuilder ruleBuilder = new RuleBuilder();
			IAuthRuleBuilderRuleOpClassifierFinished rules = null;
			rules = ruleBuilder.allow("transactions").transaction().withAnyOperation().andApplyNormalRules().andThen()
				.allow().metadata();
			for (Object val : ((ArrayList)claims.getClaimValue("scope"))) {
				// SMART on FHIR scope syntax expected.  First value is "patient" or "user"...
				String scope = (String)val;
				String resource = null;
				String[] scopeElements = scope.split("/");
				if (scopeElements.length == 1) {
					// Determine if a FHIR extended operation (preceded by dollar sign, $) is specified and if no type is specified.
					//   If so, authorize the operation for all types...
					if (scopeElements[0].startsWith("$"))
					{
						rules = rules.andThen()
							.allow().operation().named(scopeElements[0]).onAnyType();
					}
				}
				if (scopeElements.length == 2) {
					// Determine if a FHIR extended operation (preceded by dollar sign, $) is specified with an associated type.
					//   If so, authorize the operation for that type...
					if (scopeElements[0].startsWith("$"))
					{
						try {
							rules = rules.andThen()
								.allow().operation().named(scopeElements[0]).onType((Class<? extends IBaseResource>) Class.forName(String.format("org.hl7.fhir.dstu3.model.%s",
									scopeElements[1])));
						} catch (ClassNotFoundException e) {
							logger.error(String.format("Resource type specified in the scope is not valid, scope=%s, resource type=%s"),
								scope,
								scopeElements[1]);
							throw new AuthenticationException(String.format("Resource type specified in the scope is not valid, scope=%s, resource type=%s",
								scope,
								scopeElements[1]));
						}
					}
					else
					if ((scopeElements[0].compareToIgnoreCase("patient") == 0) ||
						(scopeElements[0].compareToIgnoreCase("user") == 0)) {
						// SMART on FHIR patient or user-specific clinical scope specified.  Next field is FHIR resource type or wildcard...
						String[] resourceElements = scopeElements[1].split("\\.");
						if (resourceElements.length != 2) {
							// Invalid scope syntax...
							logger.error(String.format("Invalid clinical scope syntax found, scope=%s",
								scope));
							throw new AuthenticationException(String.format("Invalid clinical scope syntax found, scope=%s",
								scope));
						}
						if (resourceElements[0].compareTo("*") == 0) {
							// Wildcard denotes all resources...
							resource = "ALL";
						} else {
							// Individual resource specified...
							resource = resourceElements[0];
						}

						// Now parse read/write specification...
						try {
							// All patients
							if (patientId == null) {
								if (resourceElements[1].compareTo("*") == 0) {
									rules = ((resource.compareTo("ALL") == 0) ? rules.andThen()
										.allow().read().allResources().withAnyId().andThen()
										.allow().write().allResources().withAnyId()
										:
										rules.andThen()
											.allow().read().resourcesOfType((Class<? extends IBaseResource>) Class.forName(String.format("org.hl7.fhir.dstu3.model.%s",
											resource))).withAnyId().andThen()
											.allow().write().resourcesOfType((Class<? extends IBaseResource>) Class.forName(String.format("org.hl7.fhir.dstu3.model.%s",
											resource))).withAnyId()
									);
								} else {
									if (resourceElements[1].compareToIgnoreCase("read") == 0) {
										rules = (resource.compareTo("ALL") == 0) ? rules.andThen()
											.allow().read().allResources().withAnyId()
											:
											rules.andThen()
												.allow().read().resourcesOfType((Class<? extends IBaseResource>) Class.forName(String.format("org.hl7.fhir.dstu3.model.%s",
												resource))).withAnyId();
									} else if (resourceElements[1].compareToIgnoreCase("write") == 0) {
										rules = (resource.compareTo("ALL") == 0) ? rules.andThen()
											.allow().write().allResources().withAnyId()
											:
											rules.andThen()
												.allow().write().resourcesOfType((Class<? extends IBaseResource>) Class.forName(String.format("org.hl7.fhir.dstu3.model.%s",
												resource))).withAnyId();
									} else {
										logger.error(String.format("Invalid operation specified in scope, scope=%s",
											scope));
										throw new AuthenticationException(String.format("Invalid operation specified in scope, scope=%s",
											scope));
									}
								}
							}
							else
							{
								// Patient compartmentalization
								if (resourceElements[1].compareTo("*") == 0) {
									rules = ((resource.compareTo("ALL") == 0) ? rules.andThen()
										.allow().read().allResources().inCompartment("Patient", patientId).andThen()
										.allow().write().allResources().inCompartment("Patient", patientId)
										:
										rules.andThen()
											.allow().read().resourcesOfType((Class<? extends IBaseResource>) Class.forName(String.format("org.hl7.fhir.dstu3.model.%s",
											resource))).inCompartment("Patient", patientId).andThen()
											.allow().write().resourcesOfType((Class<? extends IBaseResource>) Class.forName(String.format("org.hl7.fhir.dstu3.model.%s",
											resource))).inCompartment("Patient", patientId)
									);
								} else {
									if (resourceElements[1].compareToIgnoreCase("read") == 0) {
										rules = (resource.compareTo("ALL") == 0) ? rules.andThen()
											.allow().read().allResources().inCompartment("Patient", patientId)
											:
											rules.andThen()
												.allow().read().resourcesOfType((Class<? extends IBaseResource>) Class.forName(String.format("org.hl7.fhir.dstu3.model.%s",
												resource))).inCompartment("Patient", patientId);
									} else if (resourceElements[1].compareToIgnoreCase("write") == 0) {
										rules = (resource.compareTo("ALL") == 0) ? rules.andThen()
											.allow().write().allResources().inCompartment("Patient", patientId)
											:
											rules.andThen()
												.allow().write().resourcesOfType((Class<? extends IBaseResource>) Class.forName(String.format("org.hl7.fhir.dstu3.model.%s",
												resource))).inCompartment("Patient", patientId);
									} else {
										logger.error(String.format("Invalid operation specified in scope, scope=%s",
											scope));
										throw new AuthenticationException(String.format("Invalid operation specified in scope, scope=%s",
											scope));
									}
								}
							}
						} catch (ClassNotFoundException e) {
							logger.error(String.format("Resource specified in the scope is not valid, scope=%s, resource=%s"),
								scope,
								resource);
							throw new AuthenticationException(String.format("Resource specified in the scope is not valid, scope=%s, resource=%s",
								scope,
								resource));
						}
					}
					else
					{
						// Non-clinical scope encountered (i.e., launch scope)...
						logger.info(String.format("Non-patient or Non-user related scope read, info=%s",
							scope));
						continue;
//						logger.error(String.format("Invalid scope syntax - expected \"patient\" or \"user\" as first element of scope, scope=%s",
//							scop;
//						throw new AuthenticationException(String.format("Invalid scope syntax - expected \"patient\" or \"user\" as first element of scope, scope=%s",
//							scope));
					}
				}
			}

			// Rules are now constructed - create rule list and return...
			return ruleBuilder.build();
		} else {
			// Throw an HTTP 401
			throw new AuthenticationException("Bearer token not accepted");
		}
	}

	private JwtClaims checkAuthorization(String encodedAccessToken) throws InvalidJwtException, IOException, JoseException {
		try
		{
			//  Validate the JWT...
			JwtClaims jwtClaims = jwtConsumer.processToClaims(encodedAccessToken);
			logger.info("JWT validation succeeded, jwtClaims=" + jwtClaims);
			return jwtClaims;
		}
		catch (InvalidJwtException e)
		{
			logger.error(String.format("Error - invalid JWT, failed one or more claims, may be expired, info=%s",
				e.getMessage()),
				e);
			throw e;
		}
	}
}
