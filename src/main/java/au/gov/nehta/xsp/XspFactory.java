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

import java.util.HashMap;
import java.util.Map;

import au.gov.nehta.common.utils.ArgumentUtils;
import au.gov.nehta.xsp.impl.v1.SignedContainerProfileServiceImpl;
import au.gov.nehta.xsp.impl.v1.XmlSignatureProfileServiceImpl;
import au.gov.nehta.xsp.impl.v1.XspNamespaceConstants;

public class XspFactory {

    /*
     * Singleton instance.
     */
    private static final XspFactory instance = new XspFactory();

    /**
     * Returns an instance of {@code XspFactory}.
     *
     * @return {@code XspFactory} instance.
     * @throws XspException If there are errors instantiating the factory instance.
     */
    public static XspFactory getInstance() throws XspException {
        return XspFactory.instance;
    }

    /*
     * Cache of supported services for "XML Signature Profile".
     */
    private final Map<XspVersion, XmlSignatureProfileService> xmlSigServices = new HashMap<>();

    /*
     * Cache of supported services for "Signed Container Profile".
     */
    private final Map<XspVersion, SignedContainerProfileService> signedContainerServices = new HashMap<>();

    /*
     * Cache of supported services for "XML Encryption Profile".
     */
    private final Map<XspVersion, XmlEncryptionProfileService> xmlEncServices = new HashMap<>();

    /*
     * Cache of supported services for "Encrypted Container Profile".
     */
    private final Map<XspVersion, EncryptedContainerProfileService> encryptedContainerServices = new HashMap<>();

    /*
     * Private constructor to prevent instantiation.
     */
    private XspFactory() {
        addImplementationVersion1();
    }

    private void addImplementationVersion1() {
        // Set "XML Signature Profile" service for XSP versions: 1.2, 2010

        XmlSignatureProfileService xmlSigService_V_1_2 = new XmlSignatureProfileServiceImpl(XspNamespaceConstants.NS_SIGNED_PAYLOAD_V_1_2);
        XmlSignatureProfileService xmlSigService_V_2010 = new XmlSignatureProfileServiceImpl(XspNamespaceConstants.NS_SIGNED_PAYLOAD_V_2010);

        this.xmlSigServices.put(XspVersion.V_1_2, xmlSigService_V_1_2);
        this.xmlSigServices.put(XspVersion.V_2010, xmlSigService_V_2010);

        // Set "Signed Container Profile" service for XSP versions: 1.2, 2010
        // Have to create separate instances since the XML namespaces are different.
        this.signedContainerServices
                .put(
                        XspVersion.V_1_2,
                        new SignedContainerProfileServiceImpl(
                                XspNamespaceConstants.NS_SIGNED_PAYLOAD_V_1_2,
                                xmlSigService_V_1_2));
        this.signedContainerServices
                .put(
                        XspVersion.V_2010,
                        new SignedContainerProfileServiceImpl(
                                XspNamespaceConstants.NS_SIGNED_PAYLOAD_V_2010,
                                xmlSigService_V_2010));

        // Set "XML Encryption Profile" service for XSP versions: 1.2, 2010
        // Can use the same implementation since there is no difference
        XmlEncryptionProfileService xmlEncService = new au.gov.nehta.xsp.impl.v1.XmlEncryptionProfileServiceImpl();
        this.xmlEncServices.put(XspVersion.V_1_2, xmlEncService);
        this.xmlEncServices.put(XspVersion.V_2010, xmlEncService);

        // Set "Encrypted Container Profile" service for XSP versions: 1.2, 2010
        // Have to create separate instances since the XML namespaces are different.
        this.encryptedContainerServices
                .put(
                        XspVersion.V_1_2,
                        new au.gov.nehta.xsp.impl.v1.EncryptedContainerProfileServiceImpl(
                                au.gov.nehta.xsp.impl.v1.XspNamespaceConstants.NS_ENCRYPTED_PAYLOAD_V_1_2,
                                xmlEncService));
        this.encryptedContainerServices
                .put(
                        XspVersion.V_2010,
                        new au.gov.nehta.xsp.impl.v1.EncryptedContainerProfileServiceImpl(
                                au.gov.nehta.xsp.impl.v1.XspNamespaceConstants.NS_ENCRYPTED_PAYLOAD_V_2010,
                                xmlEncService));
    }

    /**
     * Returns whether that the <em>XML Signature Profile</em> is supported for a
     * given version of the <em>XML Secured Payload Profiles</em> document.
     *
     * @param version XSP version (required).
     * @return true if the <em>XML Signature Profile</em> is supported and false
     * otherwise.
     */
    public boolean isXmlSignatureProfileServiceSupported(XspVersion version) {
        ArgumentUtils.checkNotNull(version, "version");
        return this.xmlSigServices.containsKey(version);
    }

    /**
     * Returns an implementation that supports the <em>XML Signature Profile</em>
     * for a given version of the <em>XML Secured Payload Profiles</em> document.
     *
     * @param version XSP version (required).
     * @return an implementation supporting the <em>XML Signature Profile</em>.
     * @throws XspException If the <em>XML Signature Profile</em> is not supported by the
     *                      given version.
     */
    public XmlSignatureProfileService getXmlSignatureProfileService(
            XspVersion version) throws XspException {
        ArgumentUtils.checkNotNull(version, "version");

        XmlSignatureProfileService service = this.xmlSigServices.get(version);
        if (service == null) {
            String errMsg = "\"" + XmlSignatureProfileService.PROFILE_NAME
                    + "\" is not supported by XSP version, " + version + ".";
            throw new XspException(errMsg);
        }
        return service;
    }

    /**
     * Returns whether that the <em>Signed Container Profile</em> is supported for
     * a given version of the <em>XML Secured Payload Profiles</em> document.
     *
     * @param version XSP version (required).
     * @return true if the <em>Signed Container Profile</em> is supported and
     * false otherwise.
     */
    public boolean isSignedContainerProfileServiceSupported(XspVersion version) {
        ArgumentUtils.checkNotNull(version, "version");
        return this.signedContainerServices.containsKey(version);
    }

    /**
     * Returns an implementation that supports the
     * <em>Signed Container Profile</em> for a given version of the
     * <em>XML Secured Payload Profiles</em> document.
     *
     * @param version XSP version (required).
     * @return an implementation supporting the <em>Signed Container Profile</em>.
     * @throws XspException If the <em>Signed Container Profile</em> is not supported by the
     *                      given version.
     */
    public SignedContainerProfileService getSignedContainerProfileService(
            XspVersion version) throws XspException {
        ArgumentUtils.checkNotNull(version, "version");

        SignedContainerProfileService service = this.signedContainerServices
                .get(version);
        if (service == null) {
            String errMsg = "\"" + SignedContainerProfileService.PROFILE_NAME
                    + "\" is not supported by XSP version, " + version + ".";
            throw new XspException(errMsg);
        }
        return service;
    }

    /**
     * Returns whether that the <em>XML Encryption Profile</em> is supported for a
     * given version of the <em>XML Secured Payload Profiles</em> document.
     *
     * @param version XSP version (required).
     * @return true if the <em>XML Encryption Profile</em> is supported and false
     * otherwise.
     */
    public boolean isXmlEncryptionProfileServiceSupported(XspVersion version) {
        ArgumentUtils.checkNotNull(version, "version");
        return this.xmlEncServices.containsKey(version);
    }

    /**
     * Returns an implementation that supports the <em>XML Encryption Profile</em>
     * for a given version of the <em>XML Secured Payload Profiles</em> document.
     *
     * @param version XSP version (required).
     * @return an implementation supporting the <em>XML Encryption Profile</em>.
     * @throws XspException If the <em>XML Encryption Profile</em> is not supported by the
     *                      given version.
     */
    public XmlEncryptionProfileService getXmlEncryptionProfileService(
            XspVersion version) throws XspException {
        ArgumentUtils.checkNotNull(version, "version");

        XmlEncryptionProfileService service = this.xmlEncServices.get(version);
        if (service == null) {
            String errMsg = "\"" + XmlEncryptionProfileService.PROFILE_NAME
                    + "\" is not supported by XSP version, " + version + ".";
            throw new XspException(errMsg);
        }
        return service;
    }

    /**
     * Returns whether that the <em>Encrypted Container Profile</em> is supported
     * for a given version of the <em>XML Secured Payload Profiles</em> document.
     *
     * @param version XSP version (required).
     * @return true if the <em>Encrypted Container Profile</em> is supported and
     * false otherwise.
     */
    public boolean isEncryptedContainerProfileServiceSupported(XspVersion version) {
        ArgumentUtils.checkNotNull(version, "version");
        return this.encryptedContainerServices.containsKey(version);
    }

    /**
     * Returns an implementation that supports the
     * <em>Encrypted Container Profile</em> for a given version of the
     * <em>XML Secured Payload Profiles</em> document.
     *
     * @param version XSP version (required).
     * @return an implementation supporting the
     * <em>Encrypted Container Profile</em>.
     * @throws XspException If the <em>Encrypted Container Profile</em> is not supported by
     *                      the given version.
     */
    public EncryptedContainerProfileService getEncryptedContainerProfileService(
            XspVersion version) throws XspException {
        ArgumentUtils.checkNotNull(version, "version");

        EncryptedContainerProfileService service = this.encryptedContainerServices
                .get(version);
        if (service == null) {
            String errMsg = "\"" + EncryptedContainerProfileService.PROFILE_NAME
                    + "\" is not supported by XSP version, " + version + ".";
            throw new XspException(errMsg);
        }
        return service;
    }

}
