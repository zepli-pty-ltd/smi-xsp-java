package au.gov.nehta.xsp;

import java.security.cert.X509Certificate;

/**
 * Added wrapper to delegate back to CertificateValidator for backwards compatibility
 *
 * @deprecated use CertificateValidationException  instead
 */
@Deprecated
public abstract class CertificateVerifier implements CertificateValidator {

    /**
     * @deprecated use CertificateValidationException.validate instead
     */
    public abstract void verify(X509Certificate certificate)
            throws CertificateVerificationException, XspException;


    /***
     * A delegating proxy that will use verify(X509Certificate certificate) for backwards compatibility
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException, XspException {
        try {
            this.verify(certificate);
        } catch (CertificateVerificationException e) {
            throw e;
        }

    }
}
