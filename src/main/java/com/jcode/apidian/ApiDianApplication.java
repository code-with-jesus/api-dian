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
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;


import javax.xml.soap.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.*;

@SpringBootApplication
public class ApiDianApplication implements CommandLineRunner {

	private static Logger LOG = LoggerFactory.getLogger(ApiDianApplication.class);

	private Certificate x509cert;

	private PrivateKey privateKey;


	public static void main(String[] args) {
		LOG.info("STARTING THE APPLICATION");
		System.setProperty("file.encoding", "utf-8");
		System.setProperty("sun.io.unicode.encoding", "utf-8");
		SpringApplication.run(ApiDianApplication.class, args);
		LOG.info("APPLICATION FINISHED");
	}

	@Override
	public void run(String... args) {
		LOG.info("EXECUTING : command line runner");

		try {
			String certificatePath = "";
			String password = "";
			String trackId = "";


			String url = "https://vpfe-hab.dian.gov.co/WcfDianCustomerServices.svc?wsdl";

			InputStream inStream = new FileInputStream(certificatePath);

			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(inStream, password.toCharArray());

			String alias = keyStore.aliases().nextElement();
			x509cert = keyStore.getCertificate(alias);
			privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

			String response = getStatus(trackId, url);

			LOG.info("GetStatus: {}", response);

		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
			e.printStackTrace();
		}


	}
/*
	public boolean validate(Document document, String xpathSignatureNode, String xpathCertificateNode) {
		try {
			org.w3c.dom.Node signatureNode = null;//this.extractSignatureFromXmlDocument(document, xpathSignatureNode);
			Certificate certificate = null;this.extractCertificateFromXmlDocument(document, xpathCertificateNode);
			KeySelector keySelector = KeySelector.singletonKeySelector(certificate.getPublicKey());

			String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
			Provider provider = (Provider) Class.forName(providerName).getDeclaredConstructor().newInstance();
			XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM", provider);
			DOMValidateContext valContext = new DOMValidateContext(keySelector, signatureNode);
			valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
			NodeList elements = document.getElementsByTagName("xades:SignedProperties");
			if (elements.getLength() > 0) {
				valContext.setIdAttributeNS((Element) elements.item(0), null, "Id");
			}

			XMLSignature signature = signatureFactory.unmarshalXMLSignature(valContext);

			if (signature.validate(valContext)) {
				log.info("XML X.509 signature is valid :)");
				return true;
			}

		} catch (Exception ex) {
			log.error("Invalid XML X.509 signature", ex);
		}
		return false;
	}*/


	private String getStatus(String trackId, String url) {
		LOG.info("GetStatus ");
		String response = "";

		SOAPMessage soapRequest = createSOAPMessage(trackId, "http://wcf.dian.colombia/IWcfDianCustomerServices/GetStatus", url);
		response = sendSoapMsg(soapRequest, url);
		return response;
	}

	private String sendSoapMsg(SOAPMessage soapRequest, String url) {

		SOAPConnection soapConnection = null;
		SOAPMessage soapResponse = null;
		try {
			LOG.info("----------");
			LOG.info("{}", soapToString(soapRequest));
			LOG.info("----------");

			soapConnection = SOAPConnectionFactory.newInstance().createConnection();
			System.setProperty("https.protocols", "TLSv1.2");
			soapResponse = soapConnection.call(soapRequest, url);
			String message = soapToString(soapResponse);

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

	private String soapToString(SOAPMessage soapMessage) {
		try {
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			Source sourceContent = soapMessage.getSOAPPart().getContent();
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			transformer.transform(sourceContent, new StreamResult(outputStream));
			return new String(outputStream.toByteArray());

		} catch (TransformerException | SOAPException ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public SOAPMessage createSOAPMessage(String uuid, String action, String to) {
		try {
			MessageFactory messageFactory = MessageFactory.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL);
			SOAPMessage soapMessage = messageFactory.createMessage();
			SOAPEnvelope soapEnvelope = soapMessage.getSOAPPart().getEnvelope();

			soapEnvelope.removeNamespaceDeclaration("env");
			soapEnvelope.addNamespaceDeclaration("soap", "http://schemas.xmlsoap.org/soap/envelope/");
			soapEnvelope.addNamespaceDeclaration("wcf", "http://wcf.dian.colombia");
			soapEnvelope.setPrefix("soap");

			SOAPHeader soapHeader = soapMessage.getSOAPHeader();
			soapHeader.setPrefix("soap");
			soapHeader.addNamespaceDeclaration("wsa", "http://www.w3.org/2005/08/addressing");

			SOAPElement securityElement = soapHeader.addChildElement("Security", "wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			securityElement.addNamespaceDeclaration("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

			SOAPElement timestamp = securityElement.addChildElement("Timestamp", "wsu");
			timestamp.addAttribute(soapEnvelope.createName("Id", "wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"), "TS");
			timestamp.addChildElement("Created", "wsu").setValue(Instant.now().toString());
			timestamp.addChildElement("Expires", "wsu").setValue(Instant.now().plusSeconds(60).toString());

			SOAPElement binarySecurityToken = securityElement.addChildElement("BinarySecurityToken", "wsse");
			binarySecurityToken.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
			binarySecurityToken.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
			binarySecurityToken.setAttribute("wsu:Id", "X509Token");
			binarySecurityToken.addTextNode(Base64.getEncoder().encodeToString(x509cert.getEncoded()));

			SOAPElement actionElement = soapHeader.addChildElement("Action", "wsa");
			actionElement.setTextContent(action);
			SOAPElement toElement = soapHeader.addChildElement("To", "wsa");
			toElement.addAttribute(soapEnvelope.createName("Id", "wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"), "ActionTo");
			toElement.setTextContent(to);

			SOAPBody soapBody = soapMessage.getSOAPBody();
			soapBody.setPrefix("soap");
			SOAPElement status = soapBody.addChildElement("GetStatus", "wcf");
			SOAPElement trackId = status.addChildElement("trackId", "wcf");
			trackId.setTextContent(uuid);

			addSignature(securityElement);
			return soapMessage;

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	private SOAPElement addSignature(SOAPElement securityElement) throws Exception {
		String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider)Class.forName(providerName).newInstance());

		final List<Transform> transforms = new ArrayList<>(2);
		transforms.add(xmlSignatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, new ExcC14NParameterSpec(List.of("soap", "wcf"))));

		Reference referenceActionTo = xmlSignatureFactory.newReference("#ActionTo", xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null), transforms, null, null);
		CanonicalizationMethod cm = xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, new ExcC14NParameterSpec(List.of("wsa", "soap", "wcf")));
		SignatureMethod sm = xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null);
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(cm, sm, List.of(referenceActionTo));

		DOMSignContext signContext = new DOMSignContext(privateKey, securityElement);
		signContext.setDefaultNamespacePrefix("ec");
		signContext.putNamespacePrefix(XMLSignature.XMLNS, "ds");
		KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();

		DOMStructure domKeyInfo = new DOMStructure(addSecurityToken(securityElement));
		KeyInfo keyInfo = keyFactory.newKeyInfo(Collections.singletonList(domKeyInfo));
		XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		signContext.setBaseURI("");
		signature.sign(signContext);
		return securityElement;
	}

	private SOAPElement addSecurityToken(SOAPElement securityElement) throws SOAPException {
		SOAPElement securityTokenReference = securityElement.addChildElement("SecurityTokenReference","wsse");
		SOAPElement reference = securityTokenReference.addChildElement("Reference", "wsse");
		reference.setAttribute("URI", "#X509Token");
		reference.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
		securityElement.removeChild(securityTokenReference);
		return securityTokenReference;
	}
	
}
