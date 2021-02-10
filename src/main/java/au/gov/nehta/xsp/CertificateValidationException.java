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

/**
 * Exception thrown when a X.509 certificate in an XML signature could not be
 * not be validated.
 */
public class CertificateValidationException extends Exception {

    private static final long serialVersionUID = 1943605760442936336L;

    /*
     * The invalid certificate
     */
    private X509Certificate invalidCertificate;

    /**
     * Default constructor.
     */
    public CertificateValidationException() {
        super();
    }

    /**
     * Constructor that sets the error message.
     *
     * @param message
     *          the error message to set.
     */
    public CertificateValidationException(String message) {
        super(message);
    }

    /**
     * Constructor that sets the original throwable.
     *
     * @param cause
     *          the original throwable to set.
     */
    public CertificateValidationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructor that sets the error message and the original throwable.
     *
     * @param message
     *          the error message to set.
     * @param cause
     *          the original throwable to set.
     */
    public CertificateValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Returns the invalid certificate that caused the exception.
     *
     * @return invalid certificate.
     */
    public X509Certificate getInvalidCertificate() {
        return this.invalidCertificate;
    }

    /**
     * Returns the invalid certificate that caused the exception.
     *
     * @param certificate
     *          invalid certificate.
     */
    public void setInvalidCertificate(X509Certificate certificate) {
        this.invalidCertificate = certificate;
    }

}
