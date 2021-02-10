/*
 * Copyright 2008 NEHTA
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
 * Constants storing the the namespaces, namespace prefixes and element tags
 * used by the signed and encrypted payload containers.
 */
public class XspTagConstants {

    /**
     * Prefix for the encrypted payload container namespace
     */
    public static final String ENCRYPTED_PAYLOAD_NS_PREFIX = "ep";

    /**
     * Prefix for the signed payload container namespace
     */
    public static final String SIGNED_PAYLOAD_NS_PREFIX = "sp";

    /**
     * Tag of the 'encryptedPayload' element
     */
    public static final String ENCRYPTED_PAYLOAD_TAG = "encryptedPayload";

    /**
     * Qualified name of the 'ep:encryptedPayload' element
     */
    public static final String ENCRYPTED_PAYLOAD_QNAME = ENCRYPTED_PAYLOAD_NS_PREFIX + ":"
            + ENCRYPTED_PAYLOAD_TAG;

    /**
     * Tag of the 'keys' element
     */
    public static final String KEYS_TAG = "keys";

    /**
     * Qualified name of the 'ep:keys' element
     */
    public static final String KEYS_QNAME = ENCRYPTED_PAYLOAD_NS_PREFIX + ":" + KEYS_TAG;

    /**
     * Tag of the 'encryptedPayloadData' element
     */
    public static final String ENCRYPTED_PAYLOAD_DATA_TAG = "encryptedPayloadData";

    /**
     * Qualified name of the 'ep:encryptedPayloadData' element
     */
    public static final String ENCRYPTED_PAYLOAD_DATA_QNAME = ENCRYPTED_PAYLOAD_NS_PREFIX + ":"
            + ENCRYPTED_PAYLOAD_DATA_TAG;

    /**
     * Tag of the 'signedPayload' element
     */
    public static final String SIGNED_PAYLOAD_TAG = "signedPayload";

    /**
     * Qualified name of the 'sp:signedPayload' element
     */
    public static final String SIGNED_PAYLOAD_QNAME = SIGNED_PAYLOAD_NS_PREFIX + ":"
            + SIGNED_PAYLOAD_TAG;

    /**
     * Tag of the 'signatures' element
     */
    public static final String SIGNATURES_TAG = "signatures";

    /**
     * Qualified name of the 'sp:signatures' element
     */
    public static final String SIGNATURES_QNAME = SIGNED_PAYLOAD_NS_PREFIX + ":" + SIGNATURES_TAG;

    /**
     * Tag of the 'signedPayloadData' element
     */
    public static final String SIGNED_PAYLOAD_DATA_TAG = "signedPayloadData";

    /**
     * Qualified name of the 'sp:signedPayloadData' element
     */
    public static final String SIGNED_PAYLOAD_DATA_QNAME = SIGNED_PAYLOAD_NS_PREFIX + ":"
            + SIGNED_PAYLOAD_DATA_TAG;

    /**
     * Tag of the 'id' attribute.
     */
    public static final String ID_TAG = "id";
}
