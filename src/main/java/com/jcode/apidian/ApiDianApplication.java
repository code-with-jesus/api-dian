package com.jcode.apidian;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.w3c.dom.Document;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

@SpringBootApplication
public class ApiDianApplication implements CommandLineRunner {

	private static String FORMATTER_DATETIME_NO_MS = "yyyy-MM-dd'T'HH:mm:ss.SSSX";

	private static Logger LOG = LoggerFactory.getLogger(ApiDianApplication.class);

	private Certificate x509cert;

	private PrivateKey privateKey;



	public static void main(String[] args) {
		LOG.info("STARTING THE APPLICATION");
		SpringApplication.run(ApiDianApplication.class, args);
		LOG.info("APPLICATION FINISHED");
	}

	@Override
	public void run(String... args) {
		LOG.info("EXECUTING : command line runner");

		String url = "https://gtpa-webservices-input-test.azurewebsites.net/WcfDianCustomerServices.svc?wsdl";

	}

	private String getStatus(String trackId, String url) {
		LOG.info("GetStatus ");
		String response = "";

		StringBuffer buffer = new StringBuffer();
		buffer.append("<wcf:GetStatus xmlns:wcf=\"http://wcf.dian.colombia\">");
		buffer.append("<wcf:trackId>" + trackId + "</wcf:trackId>");
		buffer.append("</wcf:GetStatus>");
		SOAPMessage soapRequest = createSOAPMessage(buffer.toString(), "http://wcf.dian.colombia/IWcfDianCustomerServices/GetStatus", x509cert, privateKey);
		response = sendSoapMsg(soapRequest, url);
		return response;
	}

	private String sendSoapMsg(SOAPMessage soapRequest, String url) {

		SOAPConnection soapConnection = null;
		SOAPMessage soapResponse = null;
		try {
			soapConnection = SOAPConnectionFactory.newInstance().createConnection();
			System.setProperty("https.protocols", "TLSv1.2");
			soapResponse = soapConnection.call(soapRequest, url);
			String message = soapToString(soapResponse);
			//setResponseValues(message);
			return message;
		} catch (SOAPException  e) {
			e.printStackTrace();

		} finally {
			if (soapConnection != null)
				try {
					soapConnection.close();
				} catch (Throwable e) {}
		}
		return null;
	}

	private String soapToString(SOAPMessage soapMsg) {
		try {
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			Source sourceContent = soapMsg.getSOAPPart().getContent();
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			transformer.transform(sourceContent, new StreamResult(outputStream));
			return new String(outputStream.toByteArray());

		} catch (TransformerException | SOAPException ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public SOAPMessage createSOAPMessage(String xmlRequest, String urlActionTo, Certificate x509cert, PrivateKey privateKey) {
		try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document xmlDocument = dBuilder.parse(new ByteArrayInputStream(xmlRequest.getBytes()));
			MessageFactory messageFactory = MessageFactory.newInstance();
			SOAPMessage soapMessage = messageFactory.createMessage();
			SOAPEnvelope soapEnvelope = soapMessage.getSOAPPart().getEnvelope();
			SOAPBody soapBody = soapMessage.getSOAPBody();
			soapBody.addDocument(xmlDocument);
			soapBody.addAttribute(soapEnvelope.createName("Id", "wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"), "Body");
			SOAPHeader soapHeader = soapMessage.getSOAPHeader();
			SOAPElement securityElement = soapHeader.addChildElement("Security", "wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			securityElement.addNamespaceDeclaration("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			addBinarySecurityToken(securityElement, x509cert);
			SOAPElement timestamp = addTimestamp(securityElement, soapMessage);
			addActionTo(soapHeader, soapEnvelope, urlActionTo);
			addSignature(securityElement, soapMessage.getSOAPBody(), timestamp, privateKey);
			return soapMessage;

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	private SOAPElement addBinarySecurityToken(SOAPElement securityElement, Certificate cert) throws Exception {
		byte[] certByte = cert.getEncoded();
		SOAPElement binarySecurityToken = securityElement.addChildElement("BinarySecurityToken", "wsse");
		binarySecurityToken.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
		binarySecurityToken.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
		binarySecurityToken.setAttribute("wsu:Id", "X509Token");
		binarySecurityToken.addTextNode(Base64.getEncoder().encodeToString(certByte));
		return securityElement;
	}

	private SOAPElement addTimestamp(SOAPElement securityElement, SOAPMessage soapMessage) throws SOAPException {
		SOAPElement timestamp = securityElement.addChildElement("Timestamp", "wsu");
		SOAPEnvelope soapEnvelope = soapMessage.getSOAPPart().getEnvelope();
		timestamp.addAttribute(soapEnvelope.createName("Id", "wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"), "TS");
		timestamp.addChildElement("Created", "wsu").setValue(getCurrentDateTime());
		timestamp.addChildElement("Expires", "wsu").setValue(getCurrentDateTimePlusDelay(60L));
		return timestamp;
	}

	private void addActionTo(SOAPElement soapHeader, SOAPEnvelope soapEnvelope, String servicePoint) throws Exception {
		SOAPElement actionElement = soapHeader.addChildElement("Action", "wsa", "http://www.w3.org/2005/08/addressing");
		actionElement.setTextContent(servicePoint);
		SOAPElement toElement = soapHeader.addChildElement("To", "wsa", "http://www.w3.org/2005/08/addressing");
		toElement.setTextContent("https://gtpa-webservices-input-test.azurewebsites.net/WcfDianCustomerServices.svc");
		toElement.addAttribute(soapEnvelope.createName("Id", "wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"), "ActionTo");
	}

	private SOAPElement addSignature(SOAPElement securityElement, SOAPBody soapBody, SOAPElement timestamp, PrivateKey key) throws Exception {
		SOAPElement securityTokenReference = addSecurityToken(securityElement);
		createDetachedSignature(securityElement, key, securityTokenReference, soapBody, timestamp);
		return securityElement;
	}

	private SOAPElement addSecurityToken(SOAPElement signature) throws SOAPException {
		SOAPElement securityTokenReference = signature.addChildElement("SecurityTokenReference", "wsse");
		SOAPElement reference = securityTokenReference.addChildElement("Reference", "wsse");
		reference.setAttribute("URI", "#X509Token");
		return securityTokenReference;
	}

	private void createDetachedSignature(SOAPElement signatureElement, PrivateKey privateKey, SOAPElement securityTokenReference, SOAPBody soapBody, SOAPElement timestamp) throws Exception {
		String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider)Class.forName(providerName).newInstance());
		DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256", null);
		ArrayList<Transform> transformList = new ArrayList<>();
		List<String> prefixList1 = new ArrayList<>();
		prefixList1.add("env");
		prefixList1.add("wcf");
		C14NMethodParameterSpec c14NMethodParameterSpec1 = new ExcC14NParameterSpec(prefixList1);
		Transform envTransform = xmlSignatureFactory.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#", c14NMethodParameterSpec1);
		transformList.add(envTransform);
		ArrayList<Reference> refList = new ArrayList<>();
		Reference refActionTo = xmlSignatureFactory.newReference("#ActionTo", digestMethod, transformList, null, null);
		refList.add(refActionTo);
		List<String> prefixList = new ArrayList<>();
		prefixList.add("env");
		prefixList.add("wsa");
		prefixList.add("wcf");
		C14NMethodParameterSpec c14NMethodParameterSpec = new ExcC14NParameterSpec(prefixList);
		CanonicalizationMethod cm = xmlSignatureFactory.newCanonicalizationMethod("http://www.w3.org/2001/10/xml-exc-c14n#", c14NMethodParameterSpec);
		SignatureMethod sm = xmlSignatureFactory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(cm, sm, refList);
		DOMSignContext signContext = new DOMSignContext(privateKey, (Node)signatureElement);
		signContext.setDefaultNamespacePrefix("ds");
		signContext.putNamespacePrefix("http://www.w3.org/2000/09/xmldsig#", "ds");
		signContext.setIdAttributeNS(soapBody, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");
		signContext.setIdAttributeNS(timestamp, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");
		KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();
		DOMStructure domKeyInfo = new DOMStructure(securityTokenReference);
		KeyInfo keyInfo = keyFactory.newKeyInfo(Collections.singletonList(domKeyInfo));
		XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		signContext.setBaseURI("");
		signature.sign(signContext);
	}

	public String getCurrentDateTime() {
		DateFormat dfETC = new SimpleDateFormat(FORMATTER_DATETIME_NO_MS);
		dfETC.setTimeZone(TimeZone.getTimeZone("UTC"));
		StringBuffer dateETC = new StringBuffer(dfETC.format(new Date()));
		return dateETC.toString();
	}

	public String getCurrentDateTimePlusDelay(long delayInSeconds) {
		DateFormat dfETC = new SimpleDateFormat(FORMATTER_DATETIME_NO_MS);
		dfETC.setTimeZone(TimeZone.getTimeZone("UTC"));
		Date date = new Date();
		long timeInMsecs = date.getTime();
		date.setTime(timeInMsecs + delayInSeconds * 1000L);
		StringBuffer dateETC = new StringBuffer(dfETC.format(date));
		return dateETC.toString();
	}
}
