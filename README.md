# XML Secured Payload Profiles Library

This is the source code that provides an implementation of the
XML Secured Payload Profiles using Java.

Installation
============

To build and test the distributable package, the following must be installed:

This distribution
-----------------
1. Unpack the smi-xsp-*.zip file to the desired location.
    <XSP_HOME> will be used in this document to refer to the root
    directory of this implementation.

Java Development Kit
--------------------
1. Download and install JDK 8 Update 271 or later.
      URL: http://java.sun.com/javase/downloads/index.jsp
      <JDK_HOME> will be used in this document to refer to the root directory
      of the JDK installation.
      <JRE_HOME> will be used in this document to refer to <JDK_HOME>/jre.
2. Add <JDK_HOME>/bin to the path.
3. Create a JAVA_HOME environment variable pointing to <JDK_HOME>.

JCE Policy Files
----------------
The Java Cryptography Extension (JCE) provides cryptography services in the JDK.
The JCE policy files in the JDK download are limited in strength due to the
import control restrictions for some countries. The "unlimited strength"
capabilities are enabled by installing certain policy files into the JRE.
1. Download the JCE Unlimited Strength Jurisdiction Policy Files for the
   installed JDK version.
      URL: http://java.sun.com/javase/downloads/index.jsp
2. Unpack the downloaded ZIP file.
3. Copy the two JAR files (local_policy.jar and US_export_policy.jar) to the
   <JRE_HOME>/lib/security directory.
      Overwrite the existing JAR files in the directory.

Building and running the code
=============================

The project is supplied with a Maven pom.xml file. Use Maven to build the code.

Source code
===========

The source code is the src/main/java directory structure.

Licensing
=========

Copyright 2009 NEHTA

Copyright 2021 ADHA

Licensed under the NEHTA/ADHA Open Source (Apache) License; you may not use this
file except in compliance with the License. A copy of the License is in the
'LICENSE.txt' file, which should be provided with this work.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
