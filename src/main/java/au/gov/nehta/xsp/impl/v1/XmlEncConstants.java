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
package au.gov.nehta.xsp.impl.v1;

/**
 *
 */
public final class XmlEncConstants {

    /**
     * XML Encryption namespace
     */
    public static final String XMLENC_NS = "http://www.w3.org/2001/04/xmlenc#";

    /**
     * Prefix for the XML Encryption namespace
     */
    public static final String XMLENC_NS_PREFIX = "xenc";

    /**
     * Tag of the 'EncryptedData' element
     */
    public static final String ENCRYPTED_DATA_TAG = "EncryptedData";

    /**
     * Qualified name of the 'xenc:EncryptedData' element
     */
    public static final String ENCRYPTED_DATA_QNAME = XMLENC_NS_PREFIX + ":" + ENCRYPTED_DATA_TAG;

    /**
     * Tag of the 'EncryptedKey' element
     */
    public static final String ENCRYPTED_KEY_TAG = "EncryptedKey";

    /*
     * Private constructor to prevent instantiation.
     */
    private XmlEncConstants() {
    }

}
