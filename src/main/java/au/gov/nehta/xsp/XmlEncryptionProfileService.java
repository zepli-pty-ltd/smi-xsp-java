package au.gov.nehta.xsp;

import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500PrivateCredential;

import org.w3c.dom.Element;

/**
 * This interface provides functionality related to XML Encryption that conform
 * to the <em>XML Encryption Profile</em> in the
 * <em>XML Secured Payload Profiles</em> document.
 * <p>
 * Note: No conformance-checking is done on the XML Encryption elements. They
 * are assumed to be conforming to the profile. An exception will only be thrown
 * if an implementation cannot continue to process them.
 */
public interface XmlEncryptionProfileService {

    /**
     * Profile name constant.
     */
    String PROFILE_NAME = "XML Encryption Profile";

    /**
     * Encrypts data using XML Encryption, which conforms to
     * <em>XML Encryption Profile</em>.
     *
     * @param elementToAddEncKeysTo DOM element to add the 'xenc:EncryptedKey' elements to. Cannot be
     *                              null.
     * @param elementToEncrypt      DOM element to encrypt. Cannot be null. This element must belong
     *                              to the same DOM document as 'elementToAddEncKeysTo'. This element
     *                              will be removed from its containing document and replaced with an
     *                              'xenc:EncryptedData' element.
     * @param certificate           The {@code X509Certificate}s to use for encryption. Cannot be
     *                              null.
     * @throws XspException If there are errors in encrypting the data using XML Encryption.
     */
    void encrypt(Element elementToAddEncKeysTo, Element elementToEncrypt, X509Certificate certificate) throws XspException;

    /**
     * Encrypts data using XML Encryption, which conforms to
     * <em>XML Encryption Profile</em>.
     *
     * @param elementToAddEncKeysTo DOM element to add the 'xenc:EncryptedKey' elements to. Cannot be
     *                              null.
     * @param elementsToEncrypt     A list of DOM elements to encrypt. Cannot be null nor empty. All
     *                              elements must belong to the same DOM document as
     *                              'elementToAddEncKeysTo'. Each element will be removed from its
     *                              containing document and replaced with an 'xenc:EncryptedData'
     *                              element.
     * @param certificate           The {@code X509Certificate}s to use for encryption. Cannot be
     *                              null.
     * @throws XspException If there are errors in encrypting the data using XML Encryption.
     */
    void encrypt(Element elementToAddEncKeysTo, List<Element> elementsToEncrypt, X509Certificate certificate) throws XspException;

    /**
     * Encrypts data using XML Encryption, which conforms to
     * <em>XML Encryption Profile</em>.
     *
     * @param elementToAddEncKeysTo DOM element to add the 'xenc:EncryptedKey' elements to. Cannot be
     *                              null.
     * @param elementToEncrypt      DOM element to encrypt. Cannot be null. This element must belong
     *                              to the same DOM document as 'elementToAddEncKeysTo'. This element
     *                              will be removed from its containing document and replaced with an
     *                              'xenc:EncryptedData' element.
     * @param certificates          A list of one or more {@code X509Certificate}s to use for
     *                              encryption. Cannot be null nor empty.
     * @throws XspException If there are errors in encrypting the data using XML Encryption.
     */
    void encrypt(Element elementToAddEncKeysTo, Element elementToEncrypt, List<X509Certificate> certificates) throws XspException;

    /**
     * Encrypts data using XML Encryption, which conforms to
     * <em>XML Encryption Profile</em>.
     *
     * @param elementToAddEncKeysTo DOM element to add the 'xenc:EncryptedKey' elements to. Cannot be
     *                              null.
     * @param elementsToEncrypt     A list of DOM elements to encrypt. Cannot be null nor empty. All
     *                              elements must belong to the same DOM document as
     *                              'elementToAddEncKeysTo'. Each element will be removed from its
     *                              containing document and replaced with an 'xenc:EncryptedData'
     *                              element.
     * @param certificates          A list of one or more {@code X509Certificate}s to use for
     *                              encryption. Cannot be null nor empty.
     * @throws XspException If there are errors in encrypting the data using XML Encryption.
     */
    void encrypt(Element elementToAddEncKeysTo, List<Element> elementsToEncrypt, List<X509Certificate> certificates) throws XspException;

    /**
     * Encrypts data using XML Encryption, which conforms to
     * <em>XML Encryption Profile</em>.
     *
     * @param elementToAddEncKeysTo DOM element to add the 'xenc:EncryptedKey' elements to. Cannot be
     *                              null.
     * @param elementToEncrypt      DOM element to encrypt. Cannot be null. This element must belong
     *                              to the same DOM document as 'elementToAddEncKeysTo'. This element
     *                              will be removed from its containing document and replaced with an
     *                              'xenc:EncryptedData' element.
     * @param sessionKey            A {@code SecretKey} to use to encrypt the payload. Cannot be null.
     * @param certificate           A {@code X509Certificate} to use to secure the provided session
     *                              key.for the encryption. Cannot be null.
     * @throws XspException If there are errors in encrypting the data using XML Encryption.
     */
    void encrypt(Element elementToAddEncKeysTo, Element elementToEncrypt, SecretKey sessionKey, X509Certificate certificate) throws XspException;

    /**
     * Encrypts data using XML Encryption, which conforms to
     * <em>XML Encryption Profile</em>.
     *
     * @param elementToAddEncKeysTo DOM element to add the 'xenc:EncryptedKey' elements to. Cannot be
     *                              null.
     * @param elementsToEncrypt     A list of DOM elements to encrypt. Cannot be null nor empty. All
     *                              elements must belong to the same DOM document as
     *                              'elementToAddEncKeysTo'. Each element will be removed from its
     *                              containing document and replaced with an 'xenc:EncryptedData'
     *                              element.
     * @param sessionKey            A {@code SecretKey} to use to encrypt the payload. Cannot be null.
     * @param certificate           {@code X509Certificate} to use to secure the provided session key.
     *                              Cannot be null.
     * @throws XspException If there are errors in encrypting the data using XML Encryption.
     */
    void encrypt(Element elementToAddEncKeysTo, List<Element> elementsToEncrypt, SecretKey sessionKey, X509Certificate certificate) throws XspException;

    /**
     * Encrypts data using XML Encryption, which conforms to
     * <em>XML Encryption Profile</em>.
     *
     * @param elementToAddEncKeysTo DOM element to add the 'xenc:EncryptedKey' elements to. Cannot be
     *                              null.
     * @param elementToEncrypt      DOM element to encrypt. Cannot be null. This element must belong
     *                              to the same DOM document as 'elementToAddEncKeysTo'. This element
     *                              will be removed from its containing document and replaced with an
     *                              'xenc:EncryptedData' element.
     * @param sessionKey            A {@code SecretKey} to use to encrypt the payload. Cannot be null.
     * @param certificates          {@code X509Certificate}s to use to secure the provided session
     *                              key. Cannot be null.
     * @throws XspException If there are errors in encrypting the data using XML Encryption.
     */
    void encrypt(Element elementToAddEncKeysTo, Element elementToEncrypt, SecretKey sessionKey, List<X509Certificate> certificates) throws XspException;

    /**
     * Encrypts data using XML Encryption, which conforms to
     * <em>XML Encryption Profile</em>.
     *
     * @param elementToAddEncKeysTo DOM element to add the 'xenc:EncryptedKey' elements to. Cannot be
     *                              null.
     * @param elementsToEncrypt     A list of DOM elements to encrypt. Cannot be null nor empty. All
     *                              elements must belong to the same DOM document as
     *                              'elementToAddEncKeysTo'. Each element will be removed from its
     *                              containing document and replaced with an 'xenc:EncryptedData'
     *                              element.
     * @param sessionKey            A {@code SecretKey} to use to encrypt the payload. Cannot be null.
     * @param certificates          {@code X509Certificate}s to use to secure the provided session
     *                              key. Cannot be null.
     * @throws XspException If there are errors in encrypting the data using XML Encryption.
     */
    void encrypt(Element elementToAddEncKeysTo, List<Element> elementsToEncrypt, SecretKey sessionKey, List<X509Certificate> certificates)
            throws XspException;

    /**
     * Decrypts data that has been encrypted using XML Encryption.
     *
     * @param encryptedKeyElem  The 'xenc:EncryptedKey' DOM element. Cannot be null.. The
     *                          encrypted session key must have been used to encrypt the
     *                          'encryptedDataElem'. The 'xenc:EncryptedKey' element must have
     *                          been encrypted using the certificate in the credential.
     * @param encryptedDataElem The 'xenc:EncryptedData' DOM element. Cannot be null.
     * @param credential        The private key and X.509 certificate that will be used to perform
     *                          the decryption. Cannot be null.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the data.
     */
    void decrypt(Element encryptedKeyElem, Element encryptedDataElem, X500PrivateCredential credential) throws KeyMismatchException, XspException;

    /**
     * Decrypts data that has been encrypted using XML Encryption.
     *
     * @param encryptedKeyElems A list of 'xenc:EncryptedKey' DOM elements. Cannot be null nor
     *                          empty. The encrypted session key must have been used to encrypt
     *                          the 'encryptedDataElem'. One of the 'xenc:EncryptedKey' elements
     *                          must have been encrypted using the certificate in the credential.
     * @param encryptedDataElem The 'xenc:EncryptedData' DOM element. Cannot be null.
     * @param credential        The private key and X.509 certificate that will be used to perform
     *                          the decryption. Cannot be null.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the data.
     */
    void decrypt(List<Element> encryptedKeyElems, Element encryptedDataElem, X500PrivateCredential credential)
            throws KeyMismatchException, XspException;

    /**
     * Decrypts data that has been encrypted using XML Encryption.
     *
     * @param encryptedKeyElem   The 'xenc:EncryptedKey' DOM element. Cannot be null.. The
     *                           encrypted session key must have been used to encrypt the
     *                           'encryptedDataElem'. The 'xenc:EncryptedKey' element must have
     *                           been encrypted using the certificate in the credential.
     * @param encryptedDataElems A list of 'xenc:EncryptedData' DOM elements. Cannot be null nor
     *                           empty.
     * @param credential         The private key and X.509 certificate that will be used to perform
     *                           the decryption. Cannot be null. Must contain a non-null private
     *                           key and certificate.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the data.
     */
    void decrypt(Element encryptedKeyElem, List<Element> encryptedDataElems, X500PrivateCredential credential)
            throws KeyMismatchException, XspException;

    /**
     * Decrypts data that has been encrypted using XML Encryption.
     *
     * @param encryptedKeyElems  A list of 'xenc:EncryptedKey' DOM elements. Cannot be null nor
     *                           empty. The encrypted session key must have been used to encrypt
     *                           all the elements in 'encryptedDataElems'. One of the
     *                           'xenc:EncryptedKey' elements must have been encrypted using the
     *                           certificate in the credential.
     * @param encryptedDataElems A list of 'xenc:EncryptedData' DOM elements. Cannot be null nor
     *                           empty.
     * @param credential         The private key and X.509 certificate that will be used to perform
     *                           the decryption. Cannot be null. Must contain a non-null private
     *                           key and certificate.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the data.
     */
    void decrypt(List<Element> encryptedKeyElems, List<Element> encryptedDataElems, X500PrivateCredential credential)
            throws KeyMismatchException, XspException;

    /**
     * Decrypts data that has been encrypted using XML Encryption.
     *
     * @param encryptedKeyElem  The 'xenc:EncryptedKey' DOM element. Cannot be null.. The
     *                          encrypted session key must have been used to encrypt the
     *                          'encryptedDataElem'. The 'xenc:EncryptedKey' element must have
     *                          been encrypted using the certificate in the credential.
     * @param encryptedDataElem The 'xenc:EncryptedData' DOM element. Cannot be null.
     * @param sessionKey        A {@code SecretKey} to use to decrypt the payload. Cannot be null.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the data.
     */
    void decrypt(Element encryptedKeyElem, Element encryptedDataElem, SecretKey sessionKey) throws KeyMismatchException, XspException;

    /**
     * Decrypts data that has been encrypted using XML Encryption.
     *
     * @param encryptedKeyElems A list of 'xenc:EncryptedKey' DOM elements. Cannot be null nor
     *                          empty. The encrypted session key must have been used to encrypt
     *                          the 'encryptedDataElem'. One of the 'xenc:EncryptedKey' elements
     *                          must have been encrypted using the certificate in the credential.
     * @param encryptedDataElem The 'xenc:EncryptedData' DOM element. Cannot be null.
     * @param sessionKey        A {@code SecretKey} to use to encrypt the payload. Cannot be null.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the data.
     */
    void decrypt(List<Element> encryptedKeyElems, Element encryptedDataElem, SecretKey sessionKey) throws KeyMismatchException, XspException;

    /**
     * Decrypts data that has been encrypted using XML Encryption.
     *
     * @param encryptedKeyElem   The 'xenc:EncryptedKey' DOM element. Cannot be null.. The
     *                           encrypted session key must have been used to encrypt the
     *                           'encryptedDataElem'. The 'xenc:EncryptedKey' element must have
     *                           been encrypted using the certificate in the credential.
     * @param encryptedDataElems A list of 'xenc:EncryptedData' DOM elements. Cannot be null nor
     *                           empty.
     * @param sessionKey         A {@code SecretKey} to use to encrypt the payload. Cannot be null.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the data.
     */
    void decrypt(Element encryptedKeyElem, List<Element> encryptedDataElems, SecretKey sessionKey) throws KeyMismatchException, XspException;

    /**
     * Decrypts data that has been encrypted using XML Encryption.
     *
     * @param encryptedKeyElems  A list of 'xenc:EncryptedKey' DOM elements. Cannot be null nor
     *                           empty. The encrypted session key must have been used to encrypt
     *                           all the elements in 'encryptedDataElems'. One of the
     *                           'xenc:EncryptedKey' elements must have been encrypted using the
     *                           certificate in the credential.
     * @param encryptedDataElems A list of 'xenc:EncryptedData' DOM elements. Cannot be null nor
     *                           empty.
     * @param sessionKey         A {@code SecretKey} to use to encrypt the payload. Cannot be null.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in decrypting the data.
     */
    void decrypt(List<Element> encryptedKeyElems, List<Element> encryptedDataElems, SecretKey sessionKey) throws KeyMismatchException, XspException;

    /**
     * Gets the session key for the matching credential.
     *
     * @param encryptedKeyElems A list of 'xenc:EncryptedKey' DOM elements. Cannot be null nor
     *                          empty. The encrypted session key must have been used to encrypt
     *                          all the elements in 'encryptedDataElems'. One of the
     *                          'xenc:EncryptedKey' elements must have been encrypted using the
     *                          certificate in the credential.
     * @param encryptedDataElem The 'xenc:EncryptedData' DOM element. Cannot be null.
     * @param credential        The private key and X.509 certificate that will be used to perform
     *                          the decryption. Cannot be null. Must contain a non-null private
     *                          key and certificate.
     * @return Session key for the container.
     * @throws KeyMismatchException If an 'xenc:EncryptedKey' wasn't found for the credential that
     *                              was passed in.
     * @throws XspException         If there are any other errors in getting the session key.
     */
    Key getSessionKey(List<Element> encryptedKeyElems, Element encryptedDataElem, X500PrivateCredential credential)
            throws KeyMismatchException, XspException;

    /**
     * Gets the certificate in a key store that has been used to encrypt the
     * EncryptedKey element.
     *
     * @param encryptedKeyElem An 'xenc:EncryptedKey' DOM element. Cannot be null.
     * @param keyStore         Key store containing certificates.
     * @return certificates used to encrypt the EncryptedKey element. Return null
     * if there is no matching certificate for an EncryptedKey element.
     * @throws XspException If there are any errors in getting the encrypting certificate.
     */
    X509Certificate getEncryptingCertificate(Element encryptedKeyElem, KeyStore keyStore) throws XspException;

    /**
     * Gets the certificates in a key store that has been used to encrypt the list
     * of EncryptedKey elements.
     *
     * @param encryptedKeyElems A list of 'xenc:EncryptedKey' DOM elements. Cannot be null nor
     *                          empty.
     * @param keyStore          Key store containing certificates.
     * @return list of certificates used to encrypt the list of EncryptedKey
     * elements. If there is no matching certificate for an EncryptedKey
     * element, it is ignored.
     * @throws XspException If there are any errors in getting the encrypting certificates.
     */
    List<X509Certificate> getEncryptingCertificates(List<Element> encryptedKeyElems, KeyStore keyStore) throws XspException;

    /**
     * Checks whether the given certificate was used to create any one of a list
     * of encrypted key elements.
     *
     * @param encryptedKeyElems A list of 'xenc:EncryptedKey' DOM elements. Cannot be null nor
     *                          empty.
     * @param certificate       Certificate to check.
     * @return true if the given certificate was used to create an encrypted key
     * and false otherwise.
     * @throws XspException If there are any errors in getting the encrypting certificates.
     */
    boolean isEncryptingCertificate(List<Element> encryptedKeyElems, X509Certificate certificate) throws XspException;

}
