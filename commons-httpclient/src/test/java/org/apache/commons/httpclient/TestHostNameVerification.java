/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
// TODO: Enable after build failures are fixed
//package org.apache.commons.httpclient;
//
//import junit.framework.Test;
//import junit.framework.TestSuite;
//import org.apache.commons.httpclient.methods.GetMethod;
//import org.apache.commons.httpclient.server.SimpleSocketFactory;
//
//import java.io.IOException;
//import java.io.InputStream;
//import java.net.URL;
//import java.security.KeyStore;
//import java.security.NoSuchAlgorithmException;
//import javax.net.ssl.SSLContext;
//import javax.net.ssl.SSLException;
//import javax.net.ssl.TrustManager;
//import javax.net.ssl.TrustManagerFactory;
//
///**
// * Test Host name verification when sending https request
// */
//public class TestHostNameVerification extends HttpClientTestBase {
//    public TestHostNameVerification(String testName) throws IOException, NoSuchAlgorithmException {
//        super(testName);
//        setUseSSL(true);
//        SSLContext.setDefault(createSSLContext());
//    }
//
//    public static void main(String args[]) {
//        String[] testCaseName = { TestHostNameVerification.class.getName() };
//        junit.textui.TestRunner.main(testCaseName);
//    }
//
//    public static Test suite() {
//        return new TestSuite(TestHostNameVerification.class);
//    }
//
//    private SSLContext createSSLContext() {
//        try {
//            ClassLoader cl = SimpleSocketFactory.class.getClassLoader();
//            URL url = cl.getResource("org/apache/commons/httpclient/ssl/simpleserver.keystore");
//            KeyStore keystore = KeyStore.getInstance("jks");
//            InputStream is = null;
//            try {
//                if (url != null) {
//                    is = url.openStream();
//                }
//                keystore.load(is, "nopassword".toCharArray());
//            } finally {
//                if (is != null) {
//                    is.close();
//                }
//            }
//            TrustManagerFactory tmfactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
//            tmfactory.init(keystore);
//            TrustManager[] trustmanagers = tmfactory.getTrustManagers();
//            SSLContext sslcontext = SSLContext.getInstance("TLS");
//            sslcontext.init(null, trustmanagers, null);
//            return sslcontext;
//        } catch (Exception ex) {
//            throw new IllegalStateException(ex.getMessage());
//        }
//    }
//
//    public void testHostNameVerification() throws IOException {
//        HttpClient client = new HttpClient();
//        server.setHttpService(new FeedbackService());
//        GetMethod httpget = new GetMethod("https://" + server.getLocalAddress() + ":" + server.getLocalPort()
//                + "/test/");
//        try {
//            client.executeMethod(httpget);
//            fail("executeMethod did not throw the expected exception");
//        } catch (SSLException ex) {
//            assertTrue("Exception content.", ex.getMessage().contains("hostname in certificate didn't match"));
//        } finally {
//            // Release the connection.
//            httpget.releaseConnection();
//        }
//    }
//
//    @Override
//    public void tearDown() throws IOException {
//        super.tearDown();
//        try {
//            SSLContext.setDefault(SSLContext.getInstance("Default"));
//        } catch (NoSuchAlgorithmException e) {
//            fail("Exception occured while setting default SSLContext.");
//        }
//    }
//}
