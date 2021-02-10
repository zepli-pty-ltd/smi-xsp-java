package au.gov.nehta.xsp.impl;

import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.X509Certificate;

import au.gov.nehta.xsp.XspException;

/**
 * A collection of utility functions for X.509 certificates.
 */
public final class CertificateUtils {

    static {
        try {
            checkJCEpolicyIsUnlimited();
        } catch (XspException e) {
            System.err.println("[WARNING] " + e.getMessage());
        }
    }

    /**
     * Returns the distinguished name of a certificate's subject.
     *
     * @param certificate The {@code X509Certificate} to get the subject name from.
     * @return The subject name of the {@code X509Certificate}. Or null if the
     * certificate is null or the subject name is not set on the
     * certificate.
     */
    public static String getSubjectName(X509Certificate certificate) {
        String subjectName = null;
        if (certificate != null) {
            Principal subject = certificate.getSubjectDN();
            if (subject != null) {
                subjectName = subject.getName();
            }
        }
        return subjectName;
    }

    /**
     * Perform checks to ensure that the encryption algorithms required
     * by the XSP are supported.  Java (on most platforms) does not by default
     * contain the JCE "unlimited strength" policy files.  On these platforms
     * it is necessary to manually install JCE "unlimited strength" policy files
     * into the JRE after Java is installed.
     *
     * @throws XspException Thrown if the encryption ciphers used by XSP are not supported.
     */
    public static void checkJCEpolicyIsUnlimited() throws XspException {

        // AES

        try {
            if (javax.crypto.Cipher.getMaxAllowedKeyLength("AES") < 256)
                throw new XspException("JCE policy limits cryptography strength"
                        + ": cannot perform AES-256");
        } catch (NoSuchAlgorithmException e) {
            throw new XspException("AES encryption not supported");
        }

        // RSA

        try {
            // Actual strength needed depends on the certificates used, but
            // according to <http://en.wikipedia.org/wiki/Key_size> 1024-bits was
            // brute-forceable (in 11 months using 400 computers in 2007).
            //
            // The user might want to use a weak certificate, but we should
            // do some checking to try and avoid confusing error messages when
            // they do try to use a strong certificate and the JCE policy
            // has not been correctly setup. Better to fail some rare cases
            // rather than risk confusion in the normal case.

            if (javax.crypto.Cipher.getMaxAllowedKeyLength("RSA") < 1024)
                throw new XspException("JCE policy limits cryptography strength"
                        + ": cannot perform RSA with key size >= 1024");
        } catch (NoSuchAlgorithmException e) {
            throw new XspException("RSA encryption not supported");
        }
    }

    /*
     * Private constructor to prevent the instantiation of a utility class.
     */
    private CertificateUtils() {
    }

}
