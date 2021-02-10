package au.gov.nehta.xsp;

import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500PrivateCredential;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This interface provides functionality related to Encrypted Payloads that
 * conform to the <em>Encrypted Container Profile</em> in the
 * <em>XML Secured Payload Profiles</em> document.
 * <p>
 * Note: No conformance-checking is done on the Encrypted Payload elements. They
 * are assumed to be conforming to the profile. An exception will only be thrown
 * if an implementation cannot continue to process them.
 */
public interface EncryptedContainerProfileService {

    /**
     * Profile name constant.
     */
    String PROFILE_NAME = "Encrypted Container Profile";

    /**
     * Encrypts XML data using one certificate and and creates an
     * <code>EncryptedPayload</code> XML document.
     *
     * @param payloadDoc  A DOM {@code Document} containing the payload to be encrypted.
     *                    Cannot be null.
     * @param certificate A {@code X509Certificate}s to use for the encryption. Cannot be
     *                    null.
     * @return A DOM {@code Document} structured according to the
     * <code>encryptedPayload</code> element declared in the
     * <em>XML Secured Payload Schema</em>.
     * @throws XspException If the container document could not be created or if there are
     *                      errors in encrypting the data using XML Encryption.
     */
    Document create(Document payloadDoc, X509Certificate certificate)
            throws XspException;

    /**
     * Encrypts XML data using multiple certificates and creates an
     * <code>EncryptedPayload</code> XML document.
     *
     * @param payloadDoc   A DOM {@code Document} containing the payload to be encrypted.
     *                     Cannot be null.
     * @param certificates A list of one or more {@code X509Certificate}s to use for the
     *                     encryption. Cannot be null nor an empty list.
     * @return A DOM {@code Document} structured according to the
     * <code>encryptedPayload</code> element declared in the
     * <em>XML Secured Payload Schema</em>.
     * @throws XspException If the container document could not be created or if there are
     *                      errors in encrypting the data using XML Encryption.
     */
    Document create(Document payloadDoc, List<X509Certificate> certificates)
            throws XspException;

    /**
     * Encrypts XML data using a provided session key and creates an
     * <code>EncryptedPayload</code> XML document. The provided certificate
     * is used to secure the session key.
     *
     * @param payloadDoc  A DOM {@code Document} containing the payload to be encrypted.
     *                    Cannot be null.
     * @param sessionKey  A {@code SecretKey} to use to encrypt the payload. Cannot be null.
     * @param certificate A {@code X509Certificate} to use to secure the provided
     *                    session key. Cannot be null.
     * @return A DOM {@code Document} structured according to the
     * <code>encryptedPayload</code> element declared in the
     * <em>XML Secured Payload Schema</em>.
     * @throws XspException If the container document could not be created or if there are
     *                      errors in encrypting the data using XML Encryption.
     */
    Document create(Document payloadDoc, SecretKey sessionKey, X509Certificate certificate)
            throws XspException;

    /**
     * Encrypts XML data using a provided session key and creates an
     * <code>EncryptedPayload</code> XML document. The provided certificates
     * are used to secure the session key.
     *
     * @param payloadDoc   A DOM {@code Document} containing the payload to be encrypted.
     *                     Cannot be null.
     * @param sessionKey   A {@code SecretKey} to use to encrypt the payload. Cannot be null.
     * @param certificates A list of one or more {@code X509Certificate}s to use to
     *                     secure the provided session key. Cannot be null nor an empty list.
     * @return A DOM {@code Document} structured according to the
     * <code>encryptedPayload</code> element declared in the
     * <em>XML Secured Payload Schema</em>.
     * @throws XspException If the container document could not be created or if there are
     *                      errors in encrypting the data using XML Encryption.
     */
    Document create(Document payloadDoc, SecretKey sessionKey, List<X509Certificate> certificates)
            throws XspException;

    /**
     * Decrypts an <code>EncryptedPayload</code>, returning the payload document.
     * <p>
     * The <code>EncryptedPayload</code> must have been constructed and encrypted
     * according to the <code>EncryptedPayload</code> profile from the
     * <em>XML Secured Payload Profile</em> document.
     *
     * @param encryptedPayloadDoc A DOM {@link Document} structured according to the
     *                            <code>encryptedPayload</code> element declared in the
     *                            <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param credential          The private key and X.509 certificate that will be used to perform
     *                            the decryption. Cannot be null.
     * @return A DOM {@code Document} containing the decrypted payload.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the Encrypted
     *                              Payload.
     */
    Document getData(Document encryptedPayloadDoc,
                     X500PrivateCredential credential)
            throws KeyMismatchException,
            XspException;

    /**
     * Decrypts an <code>EncryptedPayload</code>, returning the payload document.
     * <p>
     * The <code>EncryptedPayload</code> must have been constructed and encrypted
     * according to the <code>EncryptedPayload</code> profile from the
     * <em>XML Secured Payload Profile</em> document.
     *
     * @param encryptedPayloadElem A DOM {@link Element} structured according to the
     *                             <code>encryptedPayload</code> element declared in the
     *                             <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param credential           The private key and X.509 certificate that will be used to perform
     *                             the decryption. Cannot be null.
     * @return A DOM {@code Document} containing the decrypted payload.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the Encrypted
     *                              Payload.
     */
    Document getData(Element encryptedPayloadElem,
                     X500PrivateCredential credential) throws KeyMismatchException,
            XspException;

    /**
     * Decrypts an <code>EncryptedPayload</code>, returning the payload document.
     * <p>
     * The <code>EncryptedPayload</code> must have been constructed and encrypted
     * according to the <code>EncryptedPayload</code> profile from the
     * <em>XML Secured Payload Profile</em> document.
     *
     * @param encryptedPayloadDoc A DOM {@link Document} structured according to the
     *                            <code>encryptedPayload</code> element declared in the
     *                            <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param sessionKey          A {@code SecretKey} to use to decrypt the payload. Cannot be null.
     * @return A DOM {@code Document} containing the decrypted payload.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the Encrypted
     *                              Payload.
     */
    Document getData(Document encryptedPayloadDoc,
                     SecretKey sessionKey)
            throws KeyMismatchException,
            XspException;

    /**
     * Decrypts an <code>EncryptedPayload</code>, returning the payload document.
     * <p>
     * The <code>EncryptedPayload</code> must have been constructed and encrypted
     * according to the <code>EncryptedPayload</code> profile from the
     * <em>XML Secured Payload Profile</em> document.
     *
     * @param encryptedPayloadElem A DOM {@link Element} structured according to the
     *                             <code>encryptedPayload</code> element declared in the
     *                             <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param sessionKey           A {@code SecretKey} to use to decrypt the payload. Cannot be null.
     * @return A DOM {@code Document} containing the decrypted payload.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the Encrypted
     *                              Payload.
     */
    Document getData(Element encryptedPayloadElem,
                     SecretKey sessionKey)
            throws KeyMismatchException,
            XspException;

    /**
     * Gets the session key for the container. The session key is used to encrypt
     * the data within the container.
     *
     * @param encryptedPayloadElem A DOM {@link Element} structured according to the
     *                             <code>encryptedPayload</code> element declared in the
     *                             <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param credential           The private key and X.509 certificate that will be used to perform
     *                             the decryption. Cannot be null.
     * @return Session key for the container.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in getting the session key.
     */
    Key getSessionKey(Element encryptedPayloadElem,
                      X500PrivateCredential credential)
            throws KeyMismatchException, XspException;

    /**
     * Gets the session key for the container. The session key is used to encrypt
     * the data within the container.
     *
     * @param encryptedPayloadDoc A DOM {@link Document} structured according to the
     *                            <code>encryptedPayload</code> element declared in the
     *                            <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param credential          The private key and X.509 certificate that will be used to perform
     *                            the decryption. Cannot be null.
     * @return Session key for the container.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in getting the session key.
     */
    Key getSessionKey(Document encryptedPayloadDoc, X500PrivateCredential credential)
            throws KeyMismatchException, XspException;

    /**
     * Gets the certificates in a key store that has been used to encrypt the encrypted payload element.
     *
     * @param encryptedPayloadElem A DOM {@link Element} structured according to the
     *                             <code>encryptedPayload</code> element declared in the
     *                             <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param keyStore             Key store containing certificates.
     * @return list of certificates from the key store used to encrypt the encrypted payload element.
     * @throws XspException If there are any errors in getting the encrypting certificates.
     */
    List<X509Certificate> getEncryptingCertificates(Element encryptedPayloadElem, KeyStore keyStore) throws XspException;

    /**
     * Gets the certificates in a key store that has been used to encrypt the encrypted payload document.
     *
     * @param encryptedPayloadDoc A DOM {@link Document} structured according to the
     *                            <code>encryptedPayload</code> element declared in the
     *                            <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param keyStore            Key store containing certificates.
     * @return list of certificates from the key store used to encrypt the encrypted payload document.
     * @throws XspException If there are any errors in getting the encrypting certificates.
     */
    List<X509Certificate> getEncryptingCertificates(Document encryptedPayloadDoc, KeyStore keyStore) throws XspException;

    /**
     * Checks whether the given certificate was used to create the given encrypted payload.
     *
     * @param encryptedPayloadElem A DOM {@link Element} structured according to the
     *                             <code>encryptedPayload</code> element declared in the
     *                             <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param certificate          Certificate to check.
     * @return true if the given certificate was used to create the given encrypted payload and false otherwise.
     * @throws XspException If there are any errors in getting the encrypting certificates or there are errors in the encrypted payload.
     */
    boolean isEncryptingCertificate(Element encryptedPayloadElem, X509Certificate certificate) throws XspException;

    /**
     * Checks whether the given certificate was used to create the given encrypted payload.
     *
     * @param encryptedPayloadDoc A DOM {@link Document} structured according to the
     *                            <code>encryptedPayload</code> element declared in the
     *                            <em>XML Secured Payload Schema</em>. Cannot be null.
     * @param certificate         Certificate to check.
     * @return true if the given certificate was used to create the given encrypted payload and false otherwise.
     * @throws XspException If there are any errors in getting the encrypting certificates or there are errors in the encrypted payload.
     */
    boolean isEncryptingCertificate(Document encryptedPayloadDoc, X509Certificate certificate) throws XspException;

}
