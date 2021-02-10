package au.gov.nehta.xsp.impl;

import java.security.cert.X509Certificate;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

public final class TextUtils {

    private TextUtils() {
    }

    /*
     * Return descriptive text identifying a certificate.
     */
    public static String getDesc(X509Certificate certificate) {
        return "[" +
                CertificateUtils.getSubjectName(certificate) +
                "]";
    }

    /*
     * Return descriptive text identifying an element.
     */
    public static String getDesc(Element element) {
        StringBuilder strBuilder = new StringBuilder();
        strBuilder.append("[");
        if (element == null) {
            strBuilder.append("null");
        } else {
            strBuilder.append(element.getTagName());
        }
        strBuilder.append("]");
        return strBuilder.toString();
    }

    public static String toDocString(Element node) {
        Document document = node.getOwnerDocument();
        DOMImplementationLS domImplLS = (DOMImplementationLS) document
                .getImplementation();
        LSSerializer serializer = domImplLS.createLSSerializer();
        return serializer.writeToString(node);
    }

}
