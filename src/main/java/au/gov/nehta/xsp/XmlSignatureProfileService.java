/*
 * Copyright 2009 NEHTA
 *
 * Licensed under the NEHTA Open Source (Apache) License; you may not use this
 * file except in compliance with the License. A copy of the License is in the
 * 'LICENSE.txt' file, which should be provided with this work.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package au.gov.nehta.xsp;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500PrivateCredential;

import org.w3c.dom.Element;

/**
 * This interface provides functionality related to XML Signature that conform
 * to the <em>XML Signature Profile</em> in the
 * <em>XML Secured Payload Profiles</em> document.
 * <p>
 * Note: No conformance-checking is done on the XML signatures. They are assumed
 * to be conforming to the profile. An exception will only be thrown if an
 * implementation cannot continue to process them.
 */
public interface XmlSignatureProfileService {

    /**
     * Profile name constant.
     */
    String PROFILE_NAME = "XML Signature Profile";

    /**
     * Signs an XML DOM element. The generated XML signature will conform to the
     * <em>XML Signature Profile</em> and is added to a specified DOM element.
     *
     * @param elementToAddSigTo DOM element to add the signature to. Cannot be null.
     * @param elementToSign     DOM element to sign. Cannot be null. This element must belong to
     *                          the same DOM document as 'elementToAddSigTo'.
     * @param credential        Private credential to sign with. Cannot be null. Both the private
     *                          key and the public certificate must be provided.
     * @throws XspException If there are any errors generating the signature.
     */
    void sign(Element elementToAddSigTo, Element elementToSign,
              X500PrivateCredential credential) throws XspException;

    /**
     * Signs a list of XML DOM elements. The generated XML signature will conform
     * to the <em>XML Signature Profile</em> and is added to a specified DOM
     * element.
     *
     * @param elementToAddSigTo DOM element to add the signature to. Cannot be null.
     * @param elementsToSign    DOM elements to sign. Cannot be null nor empty. These elements
     *                          must belong to the same DOM document as 'elementToAddSigTo'.
     * @param credential        Private credential to sign with. Cannot be null. Both the private
     *                          key and the public certificate must be provided.
     * @throws XspException If there are any errors generating the signature.
     */
    void sign(Element elementToAddSigTo, List<Element> elementsToSign,
              X500PrivateCredential credential) throws XspException;

    /**
     * Signs a XML DOM element with multiple credentials. Multiple XML signatures
     * will be generated; one for each set of credentials. The generated XML
     * signature will conform to the <em>XML Signature Profile</em> and is added
     * to a specified DOM element.
     *
     * @param elementToAddSigTo DOM element to add the signatures to. Cannot be null.
     * @param elementToSign     DOM element to sign. Cannot be null. This element must belong to
     *                          the same DOM document as 'elementToAddSigTo'.
     * @param credentials       Private credentials to sign with. Cannot be null nor empty. Both
     *                          the private key and the public certificate for each credential
     *                          must be provided.
     * @throws XspException If there are any errors generating the signature.
     */
    void sign(Element elementToAddSigTo, Element elementToSign,
              List<X500PrivateCredential> credentials) throws XspException;

    /**
     * Signs a list of XML DOM elements with multiple credentials. Multiple XML
     * signatures will be generated; one for each set of credentials. Each
     * generated XML signature will conform to the <em>XML Signature Profile</em>
     * and is added to a specified DOM element.
     *
     * @param elementToAddSigTo DOM element to add the signatures to. Cannot be null.
     * @param elementsToSign    DOM elements to sign. Cannot be null nor empty. These elements
     *                          must belong to the same DOM document as 'elementToAddSigTo'.
     * @param credentials       Private credentials to sign with. Cannot be null nor empty. Both
     *                          the private key and the public certificate for each credential
     *                          must be provided.
     * @throws XspException If there are any errors generating the signature.
     */
    void sign(Element elementToAddSigTo, List<Element> elementsToSign,
              List<X500PrivateCredential> credentials) throws XspException;

    /**
     * Checks the validity of an XML Signature element using a custom way to
     * verify the signing certificate. The XML Signature element is assumed to
     * conform to the <em>XML Signature Profile</em>. There are two stages to
     * checking the XML Signature. First, the signature value is validated using
     * the public key in the signing certificate. Second, the signing certificate
     * is verified, e.g. ensure that it is trusted and it hasn't been revoked.
     *
     * @param signatureElem        Signature element to check. Cannot be null.
     * @param certificateValidator Callback implementation to validate the signing certificate. Cannot
     *                             be null.
     * @throws SignatureValidationException   If a signature value can't be validated using the public key in
     *                                        its signing certificate.
     * @throws CertificateValidationException If a signing certificate is invalid.
     * @throws XspException                   If there are any other errors checking the signature.
     */
    void check(Element signatureElem, CertificateValidator certificateValidator)
            throws SignatureValidationException, CertificateValidationException,
            XspException;

    /**
     * Checks the validity of XML Signature elements using a custom way to verify
     * the signing certificates. The XML Signature elements are assumed to conform
     * to the <em>XML Signature Profile</em>. There are two stages to checking an
     * XML Signature. First, the signature value is validated using the public key
     * in the signing certificate. Second, the signing certificate is verified,
     * e.g. ensure that it is trusted and it hasn't been revoked.
     *
     * @param signatureElems       A list of signature elements to check. Cannot be null nor empty.
     * @param certificateValidator Callback implementation to validate signing certificates. Cannot be
     *                             null.
     * @throws SignatureValidationException   If a signature value can't be validated using the public key in
     *                                        its signing certificate.
     * @throws CertificateValidationException If a signing certificate is invalid or can't be verified.
     * @throws XspException                   If there are any other errors checking the signature.
     */
    void check(List<Element> signatureElems,
               CertificateValidator certificateValidator)
            throws SignatureValidationException, CertificateValidationException,
            XspException;

    /**
     * Get the {@code X509Certificate} from an XML Signature element.
     *
     * @param signatureElem Required.  The XML Signature element.
     * @return The {@code X509Certificate} from an XML Signature element.
     * @throws XspException If there are any errors extracting the DigestValue.
     */
    X509Certificate getSigningCertificate(Element signatureElem) throws XspException;

    /**
     * Get the 'DigestValue' from an XML Signature element.
     *
     * @param signatureElem Required.  The XML Signature element.
     * @return Map of reference URI to the 'DigestValue' from an XML Signature element.
     * @throws XspException If there are any errors extracting the DigestValue.
     */
    Map<String, byte[]> getDigestValues(Element signatureElem) throws XspException;

}
