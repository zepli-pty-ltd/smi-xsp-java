/*
 * Copyright 2009 - 2021 NEHTA
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
package au.gov.nehta.common.utils;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import jakarta.xml.bind.*;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import java.io.IOException;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class containing JAXB-related functions.
 */
public final class JaxbUtils {

    /*
     * Cache of package name to JAXB context objects.
     */
    private static Map<String, JAXBContext> contextCache = new HashMap<>();

    /**
     * Unmarshals the XML data in a DOM node into a Java object using JAXB. This
     * method simplifies the call to the method: {@code
     * javax.xml.bind.Unmarshaller#unmarshal(Source)}.
     *
     * @param <T>       The type of class.
     * @param xmlNode   DOM node to read the XML data from. Cannot be null.
     * @param jaxbClass JAXB-generated class that represents the XML data as a Java class.
     *                  Cannot be null.
     * @return Instance of type specified in the 'jaxbClass' containing data from
     * the 'xmlNode'.
     * @throws JAXBException Exception if any issues arise.
     */
    public static <T> T unmarshal(Node xmlNode, Class<T> jaxbClass)
            throws JAXBException {
        assert (xmlNode != null) : "'xmlNode' is null.";
        assert (jaxbClass != null) : "'jaxbClass' is null.";

        return unmarshal(new DOMSource(xmlNode), jaxbClass);
    }

    /**
     * Unmarshals the XML data from a character stream into a Java object using
     * JAXB. This method simplifies the call to the method: {@code
     * javax.xml.bind.Unmarshaller#unmarshal(Source)}.
     *
     * @param <T>       The type of the class.
     * @param reader    Character stream to read the XML data from. Cannot be null.
     * @param jaxbClass JAXB-generated class that represents the XML data as a Java class.
     *                  Cannot be null.
     * @return Instance of type specified in the 'jaxbClass' containing data from
     * the 'xmlNode'.
     * @throws JAXBException Exception if anything goes wrong.
     */
    public static <T> T unmarshal(Reader reader, Class<T> jaxbClass)
            throws JAXBException {
        assert (reader != null) : "'reader' is null.";
        assert (jaxbClass != null) : "'jaxbClass' is null.";

        return unmarshal(new StreamSource(reader), jaxbClass);
    }

    private static <T> T unmarshal(Source xmlContents, Class<T> jaxbClass)
            throws JAXBException {
        assert (xmlContents != null);
        assert (jaxbClass != null);

        // Create unmarshaller
        JAXBContext context = getContext(jaxbClass);
        Unmarshaller unmarshaller = context.createUnmarshaller();

        // Parse XML
        JAXBElement<T> jaxbElem = unmarshaller.unmarshal(xmlContents, jaxbClass);
        return jaxbElem.getValue();
    }

    /**
     * Marshals a JAXBElement object into XML data to write to a character stream.
     * This method simplifies the call to the method: {@code
     * javax.xml.bind.Marshaller#marshal(Object, Writer)}. A JAXBElement can be
     * created from the ObjectFactory generated by JAXB for each package.
     *
     * @param value  JAXBElement to marshal into XML data. Cannot be null.
     * @param output Character stream to write to. Cannot be null.
     * @throws JAXBException Exception if handling JAXBElement goes wrong.
     * @throws IOException   Exception if problems with output.
     */
    public static void marshal(JAXBElement<?> value, Writer output)
            throws JAXBException, IOException {
        assert (value != null) : "'value' is null.";
        assert (output != null) : "'output' is null.";

        JAXBContext context = getContext(value.getDeclaredType());
        Marshaller marshaller = context.createMarshaller();
        marshaller.marshal(value, output);
        output.flush();
    }

    /**
     * Marshals a JAXBElement object into a XML data string. This method
     * simplifies the call to the method: {@code
     * javax.xml.bind.Marshaller#marshal(Object, Writer)}. A JAXBElement can be
     * created from the ObjectFactory generated by JAXB for each package.
     *
     * @param value JAXBElement to marshal into XML data. Cannot be null.
     * @return XML representation of the JAXBElement.
     * @throws JAXBException Exception raised if handling JAXBElement goes wrong.
     */
    public static String marshalToString(JAXBElement<?> value) throws JAXBException {
        assert (value != null) : "'value' is null.";

        JAXBContext context = getContext(value.getDeclaredType());
        Marshaller marshaller = context.createMarshaller();
        StringWriter writer = new StringWriter();
        marshaller.marshal(value, writer);
        writer.flush();
        return writer.toString();
    }

    /**
     * Marshals a JAXBElement object into a DOM document. This method
     * simplifies the call to the method: {@code
     * javax.xml.bind.Marshaller#marshal(Object, Node)}. A JAXBElement can be
     * created from the ObjectFactory generated by JAXB for each package.
     *
     * @param value JAXBElement to marshal into XML data. Cannot be null.
     * @return XML DOM representation of the JAXBElement.
     * @throws JAXBException                Exception raised if handling JAXBElement goes wrong.
     * @throws ParserConfigurationException Exception if parser problems arise.
     */
    public static Document marshalToDom(JAXBElement<?> value) throws JAXBException,
            ParserConfigurationException {
        assert (value != null) : "'value' is null.";

        JAXBContext context = getContext(value.getDeclaredType());
        Marshaller marshaller = context.createMarshaller();
        Document doc = DomUtils.newDocument();
        marshaller.marshal(value, doc);
        return doc;
    }

    private static JAXBContext getContext(Class<?> jaxbClass) throws JAXBException {
        assert (jaxbClass != null);
        assert (jaxbClass.getPackage() != null);

        return getContext(jaxbClass.getPackage().getName());
    }

    private static JAXBContext getContext(String packageName)
            throws JAXBException {
        assert (packageName != null);

        JAXBContext context = JaxbUtils.contextCache.get(packageName);
        if (context == null) {
            context = JAXBContext.newInstance(packageName);
            JaxbUtils.contextCache.put(packageName, context);
        }
        return context;
    }
}
