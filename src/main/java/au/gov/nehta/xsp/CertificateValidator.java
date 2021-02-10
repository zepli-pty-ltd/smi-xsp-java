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

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

/**
 * Callback interface used by the {@link XmlSignatureProfileService} to verify
 * certificates in an XML signature.
 *
 * <p>Example implementation using EHealthPKI:</p>
 * <pre>
 * public class EHealthPKICertificateVerifier implements CertificateVerifier {
 *
 *   private final EHealthPKI ehealthPKI;
 *
 *   public EHealthPKICertificateVerifier(EHealthPKI ehealthPKI) {
 *    this.ehealthPKI = ehealthPKI;
 *   }
 *
 *   public void verify(X509Certificate certificate)
 *       throws CertificateVerificationException, XspException {
 *     // Validate certificate using EHealth PKI
 *     ValidationResult validationResult = this.ehealthPKI
 *         .validateSigningCertificate(certificate);
 *     ValidationStatus validationStatus = validationResult.getStatus();
 *
 *     if (validationStatus == ValidationStatus.Invalid) {
 *       StringBuilder errMsg = new StringBuilder();
 *       errMsg.append("Invalid certificate: ");
 *       errMsg.append(CertificateUtils.getSubjectName(certificate));
 *       errMsg.append(".");
 *       for (String subErrMsg : validationResult.getErrorMessages()) {
 *         errMsg.append(" ");
 *         errMsg.append(subErrMsg);
 *       }
 *       CertificateVerificationException e = new CertificateVerificationException(
 *           errMsg.toString());
 *       e.setInvalidCertificate(certificate);
 *       throw e;
 *     }
 *
 *    if (validationStatus == ValidationStatus.Unknown) {
 *       StringBuilder errMsg = new StringBuilder();
 *       errMsg.append("Unknown status of certificate: ");
 *       errMsg.append(CertificateUtils.getSubjectName(certificate));
 *       errMsg.append(".");
 *      for (String subErrMsg : validationResult.getErrorMessages()) {
 *         errMsg.append(" ");
 *         errMsg.append(subErrMsg);
 *       }
 *       throw new XspException(errMsg.toString());
 *    }
 *   }
 *
 * }
 * </pre>
 */
public interface CertificateValidator {

    /**
     * Validates that a given certificate is valid. It must be checked to be
     * current and not revoked. It must be checked up the chain to a known
     * {@link TrustAnchor}. All certificates that make up the chain are also
     * checked for validity.
     *
     * @param certificate X.509 certificate to check. Cannot be null.
     * @throws CertificateValidationException Thrown when the certificate could not be verified.
     * @throws XspException                   Thrown in the case of other errors.
     */
    void validate(X509Certificate certificate)
            throws CertificateValidationException, XspException;

}
