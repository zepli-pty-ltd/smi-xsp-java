package au.gov.nehta.xsp;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.x500.X500PrivateCredential;

import org.w3c.dom.Document;

/**
 * This interface provides functionality related to Signed Payloads that conform
 * to the <em>Signed Container Profile</em> in the
 * <em>XML Secured Payload Profiles</em> document.
 *
 * Note: No conformance-checking is done on the Signed Payloads. They are
 * assumed to be conforming to the profile. An exception will only be thrown if
 * an implementation cannot continue to process a Signed Payload.
 */
public interface SignedContainerProfileService {

    /**
     * Profile name constant.
     */
    String PROFILE_NAME = "Signed Container Profile";

    /**
     * Signs XML data and creates an <code>SignedPayload</code> XML document using
     * a set of private credentials.
     *
     * @param payloadDoc
     *          A DOM {@code Document} containing the payload to be signed. Cannot
     *          be null.
     * @param credential
     *          Private credentials to use when creating the signature. Cannot be
     *          null nor empty. Each key pair must have a certificate and private
     *          key.
     * @return A DOM {@code Document} structured according to the
     *         <code>signedPayload</code> element declared in the
     *         <em>XML Secured Payload Schema</em>.
     * @throws XspException
     *           If there are failures when signing the payload or creating the
     *           SignedPayload container document.
     */
    Document create(Document payloadDoc, X500PrivateCredential credential)
            throws XspException;

    /**
     * Signs XML data and creates a <code>SignedPayload</code> XML document using
     * multiple private credentials.
     *
     * @param payloadDoc
     *          A DOM {@code Document} containing the payload to be signed. Cannot
     *          be null.
     * @param credentials
     *          A list of private credentials to use when creating signatures.
     *          Cannot be null nor empty. Each key pair must have a certificate
     *          and private key.
     * @return A DOM {@code Document} structured according to the
     *         <code>signedPayload</code> element declared in the
     *         <em>XML Secured Payload Schema</em>.
     * @throws XspException
     *           If there are failures when signing the payload or creating the
     *           SignedPayload container document.
     */
    Document create(Document payloadDoc, List<X500PrivateCredential> credentials)
            throws XspException;

    /**
     * Extract the payload data from the SignedPayload {@code Document}.
     *
     * @param containerDoc
     *          A DOM {@code Document} structured according to the
     *          <code>signedPayload</code> element declared in the
     *          <em>XML Secured Payload Schema</em>. Cannot be null.
     * @return A DOM {@code Document} containing the payload element.
     *
     * @throws XspException
     *           If there are failures when extracting the payload XML data.
     */
    Document getData(Document containerDoc) throws XspException;

    /**
     * Checks the signatures in a <code>SignedPayload</code> XML document using a
     * custom way to verify certificates. Each signature is validated and its
     * certificate is verified, e.g. it's still valid and not yet revoked.
     *
     * @param containerDoc
     *          A DOM {@link Document} structured according to the
     *          <code>signedPayload</code> element declared in the
     *          <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param certificateValidator
     *          Callback implementation to validate the signing certificate. Cannot
     *          be null.
     * @throws SignatureValidationException
     *           If a signature value can't be validated using the public key in
     *           its signing certificate.
     * @throws CertificateValidationException
     *           If a signing certificate is invalid or can't be verified.
     * @throws XspException
     *           If there are any other errors checking the signatures.
     */
    void check(Document containerDoc,
               CertificateValidator certificateValidator)
            throws SignatureValidationException,
            CertificateValidationException, XspException;

    /**
     * Get the public {@code X509Certificate}s used to verify the digital signatures.
     *
     * @param containerDoc
     *          A DOM {@link Document} structured according to the
     *          <code>signedPayload</code> element declared in the
     *          <em>XML Secured Payload Schema</em>. Cannot be null.
     * @return A list of public {@code X509Certificate}s used to verify the digital signatures.
     *         (in the order that the signature appears in the container document)
     * @throws XspException
     *            On error.
     */
    List<X509Certificate> getSigningCertificates(Document containerDoc) throws XspException;

    /**
     * Get the 'DigestValue' of each signature in a <code>SignedPayload</code> XML document.
     *
     * @param containerDoc
     *          A DOM {@link Document} structured according to the
     *          <code>signedPayload</code> element declared in the
     *          <em>XML Secured Payload Schema</em>. Cannot be null.
     *
     * @return The 'DigestValue' of each signature in a <code>SignedPayload</code> XML document.
     *         (in the order that the signature appears in the container document)
     *
     * @throws XspException
     *           If there are any other errors extracting the digest values.
     */
    List<byte[]> getDigestValues(Document containerDoc) throws XspException;

}
