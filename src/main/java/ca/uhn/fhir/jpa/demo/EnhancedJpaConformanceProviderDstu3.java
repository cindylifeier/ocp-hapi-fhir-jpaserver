package ca.uhn.fhir.jpa.demo;

import ca.uhn.fhir.jpa.dao.DaoConfig;
import ca.uhn.fhir.jpa.dao.IFhirSystemDao;
import ca.uhn.fhir.jpa.provider.dstu3.JpaConformanceProviderDstu3;
import ca.uhn.fhir.rest.server.RestfulServer;
import ca.uhn.fhir.rest.server.exceptions.InternalErrorException;
import org.hl7.fhir.dstu3.model.Bundle;
import org.hl7.fhir.dstu3.model.CapabilityStatement;
import org.hl7.fhir.dstu3.model.CodeableConcept;
import org.hl7.fhir.dstu3.model.Coding;
import org.hl7.fhir.dstu3.model.Extension;
import org.hl7.fhir.dstu3.model.Meta;
import org.hl7.fhir.dstu3.model.UriType;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

public class EnhancedJpaConformanceProviderDstu3 extends JpaConformanceProviderDstu3 {

	private static String ConformancePropertiesFile = FhirServerProperties.conformancePropertiesFile;

	public EnhancedJpaConformanceProviderDstu3(RestfulServer theRestfulServer, IFhirSystemDao<Bundle, Meta> theSystemDao, DaoConfig theDaoConfig){
		super(theRestfulServer, theSystemDao, theDaoConfig);
	}

	@Override
	public CapabilityStatement getServerConformance(HttpServletRequest request){
		CapabilityStatement capabilityStatement = super.getServerConformance(request);
		return addCapabilityStatement(capabilityStatement);
	}

	public CapabilityStatement addCapabilityStatement(CapabilityStatement capabilityStatement){
		try {
			Properties properties = new Properties();
			properties.load(new FileInputStream(ConformancePropertiesFile));
			String urisEndpointExtensionUrl = properties.getProperty("urisEndpointExtensionUrl");
			String token = properties.getProperty("token");
			String authorize = properties.getProperty("authorize");
			String register = properties.getProperty("register");

			List<CapabilityStatement.CapabilityStatementRestComponent> restList = capabilityStatement.getRest();

			CapabilityStatement.CapabilityStatementRestComponent rest = restList.get(0);
			CapabilityStatement.CapabilityStatementRestSecurityComponent restSecurity = rest.getSecurity();

			Extension conformanceExtension = new Extension(urisEndpointExtensionUrl);
			conformanceExtension.addExtension(new Extension("authorize", new UriType(authorize)));
			conformanceExtension.addExtension(new Extension("token", new UriType(token)));
			conformanceExtension.addExtension(new Extension("register", new UriType(register)));

			restSecurity.addExtension(conformanceExtension);
			CodeableConcept codeableConcept = new CodeableConcept();
			Coding smartOnFhirCoding = new Coding("http://hl7.org/fhir/restful-security-service", "SMART-on-FHIR", "SMART-on-FHIR");
			codeableConcept.getCoding().add(smartOnFhirCoding);
			codeableConcept.setText("OAuth2 using SMART-on-FHIR profile (see http://docs.smarthealthit.org)");
			restSecurity.getService().add(codeableConcept);
		} catch (IOException var2) {
			throw new InternalErrorException(String.format("Error encountered loading Conformance.properties file, %s, info=%s", ConformancePropertiesFile, var2.getMessage()), var2);
		}

		return capabilityStatement;
	}

}
