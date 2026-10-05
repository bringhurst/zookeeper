/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZKTestCase;
import org.apache.zookeeper.common.X509KeyType;
import org.apache.zookeeper.common.X509TestHelpers;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.MockServerCnxn;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

public class X509IdentityMappingTest extends ZKTestCase {

    private static final String CLIENT_URI = "spiffe://example.test/workload/client";
    private static final String URI_ID = "uri:" + CLIENT_URI;
    private static final String DN_ID = "CN=CLIENT";
    private static int providerPosition;
    private static KeyPair caKeys;
    private static X509Certificate caCert;
    private static KeyPair clientKeys;
    private static X509Certificate uriCert;
    private static X509Certificate legacyCert;
    private static X509TrustManager trustManager;
    private String previousSuperUser;

    @BeforeAll
    public static void createCertificates() throws Exception {
        providerPosition = Security.addProvider(new BouncyCastleProvider());
        caKeys = X509TestHelpers.generateKeyPair(X509KeyType.EC);
        caCert = X509TestHelpers.newSelfSignedCert("Test CA", caKeys);
        clientKeys = X509TestHelpers.generateKeyPair(X509KeyType.EC);
        uriCert = certificateWithUri(CLIENT_URI);
        legacyCert = X509TestHelpers.newCert(caCert, caKeys, "CLIENT", clientKeys.getPublic());
        KeyStore anchors = KeyStore.getInstance("JKS");
        anchors.load(null, null);
        anchors.setCertificateEntry("ca", caCert);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(anchors);
        trustManager = (X509TrustManager) factory.getTrustManagers()[0];
    }

    @AfterAll
    public static void removeProvider() {
        if (providerPosition != -1) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    @BeforeEach
    public void clearSuperUser() {
        previousSuperUser = System.clearProperty(X509AuthenticationProvider.ZOOKEEPER_X509AUTHENTICATIONPROVIDER_SUPERUSER);
    }

    @AfterEach
    public void restoreSuperUser() {
        if (previousSuperUser == null) {
            System.clearProperty(X509AuthenticationProvider.ZOOKEEPER_X509AUTHENTICATIONPROVIDER_SUPERUSER);
        } else {
            System.setProperty(X509AuthenticationProvider.ZOOKEEPER_X509AUTHENTICATIONPROVIDER_SUPERUSER, previousSuperUser);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testDefaultStillUsesOnlySubjectDn(boolean http) {
        X509AuthenticationProvider provider = new X509AuthenticationProvider(trustManager, null);
        assertEquals(Collections.singletonList(new Id("x509", DN_ID)), authenticate(provider, uriCert, http, true));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testExistingSingleIdentityOverrideIsPreserved(boolean http) {
        X509AuthenticationProvider provider = new X509AuthenticationProvider(trustManager, null) {
            @Override
            protected String getClientId(X509Certificate certificate) {
                return "existing-custom-id";
            }

            @Override
            public String getScheme() {
                return "custom";
            }
        };
        assertEquals(Collections.singletonList(new Id("custom", "existing-custom-id")), authenticate(provider, uriCert, http, true));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testDualIdentitiesSupportMigrationWithExactMatching(boolean http) {
        UriIdentityProvider provider = new UriIdentityProvider(true);
        List<Id> identities = authenticate(provider, uriCert, http, true);
        assertEquals(Arrays.asList(new Id("x509", DN_ID), new Id("x509", URI_ID)), identities);
        assertTrue(provider.isValid(DN_ID));
        assertTrue(provider.isValid(URI_ID));
        assertFalse(provider.isValid("uri:not-an-absolute-uri"));
        assertTrue(identities.stream().anyMatch(id -> provider.matches(id.getId(), DN_ID)));
        assertTrue(identities.stream().anyMatch(id -> provider.matches(id.getId(), URI_ID)));
        assertFalse(identities.stream().anyMatch(id -> provider.matches(id.getId(), "uri:spiffe://other.test/workload/client")));
        assertFalse(identities.stream().anyMatch(id -> provider.matches(id.getId(), "client")));
        assertEquals(Collections.singletonList(new Id("x509", DN_ID)), authenticate(provider, legacyCert, http, true));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testUriOnlyPolicyDoesNotFallBackToDn(boolean http) {
        UriIdentityProvider provider = new UriIdentityProvider(false);
        assertEquals(Collections.singletonList(new Id("x509", URI_ID)), authenticate(provider, uriCert, http, true));
        assertTrue(authenticate(provider, legacyCert, http, false).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testMalformedIdentityDoesNotFallBackToDn(boolean http) throws Exception {
        X509Certificate malformed = certificateWithUri("not-an-absolute-uri");
        assertTrue(authenticate(new UriIdentityProvider(true), malformed, http, false).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testMappingExceptionRejectsEvenAnOtherwisePrivilegedDn(boolean http) {
        System.setProperty(X509AuthenticationProvider.ZOOKEEPER_X509AUTHENTICATIONPROVIDER_SUPERUSER, DN_ID);
        X509AuthenticationProvider provider = new X509AuthenticationProvider(trustManager, null) {
            @Override
            protected Collection<String> getClientIds(X509Certificate certificate) throws CertificateException {
                throw new CertificateException("Identity policy rejected this otherwise trusted certificate");
            }
        };
        assertTrue(authenticate(provider, uriCert, http, false).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testUntrustedCertificateNeverReachesIdentityMapping(boolean http) throws Exception {
        X509AuthenticationProvider provider = new X509AuthenticationProvider(trustManager, null) {
            @Override
            protected Collection<String> getClientIds(X509Certificate certificate) {
                throw new AssertionError("Must validate certificate trust before extracting identities");
            }
        };
        X509Certificate untrusted = X509TestHelpers.newSelfSignedCert("Other CA", clientKeys);
        assertTrue(authenticate(provider, untrusted, http, false).isEmpty());
        assertTrue(authenticate(provider, null, http, false).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testDuplicatesAreIgnoredAndSuperuserIsExplicit(boolean http) {
        X509AuthenticationProvider provider = new X509AuthenticationProvider(trustManager, null) {
            @Override
            protected Collection<String> getClientIds(X509Certificate certificate) {
                return Arrays.asList(DN_ID, URI_ID, DN_ID, URI_ID);
            }
        };
        assertEquals(Arrays.asList(new Id("x509", DN_ID), new Id("x509", URI_ID)), authenticate(provider, uriCert, http, true));
        System.setProperty(X509AuthenticationProvider.ZOOKEEPER_X509AUTHENTICATIONPROVIDER_SUPERUSER, URI_ID);
        assertEquals(Arrays.asList(new Id("x509", DN_ID), new Id("super", URI_ID), new Id("x509", URI_ID)),
                authenticate(provider, uriCert, http, true));
    }

    public static Stream<Arguments> invalidIdentities() {
        List<Collection<String>> invalid = Arrays.asList(null, Collections.emptyList(), Arrays.asList(DN_ID, null), Arrays.asList(DN_ID, ""));
        return invalid.stream().flatMap(ids -> Stream.of(Arguments.of(ids, false), Arguments.of(ids, true)));
    }

    @ParameterizedTest
    @MethodSource("invalidIdentities")
    public void testInvalidMappingPublishesNoPartialIdentities(Collection<String> ids, boolean http) {
        System.setProperty(X509AuthenticationProvider.ZOOKEEPER_X509AUTHENTICATIONPROVIDER_SUPERUSER, DN_ID);
        X509AuthenticationProvider provider = new X509AuthenticationProvider(trustManager, null) {
            @Override
            protected Collection<String> getClientIds(X509Certificate certificate) {
                return ids;
            }
        };
        assertTrue(authenticate(provider, uriCert, http, false).isEmpty());
    }

    private static X509Certificate certificateWithUri(String uri) throws Exception {
        return X509TestHelpers.newCert(caCert, caKeys, "CLIENT", clientKeys.getPublic(),
                builder -> builder.replaceExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, uri))));
    }

    private static List<Id> authenticate(X509AuthenticationProvider provider, X509Certificate cert, boolean http, boolean success) {
        X509Certificate[] chain = cert == null ? null : new X509Certificate[]{cert, caCert};
        if (http) {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getAttribute(X509AuthenticationProvider.X509_CERTIFICATE_ATTRIBUTE_NAME)).thenReturn(chain);
            List<Id> identities = provider.handleAuthentication(request, null);
            assertEquals(success, !identities.isEmpty());
            return identities;
        }
        MockServerCnxn connection = new MockServerCnxn();
        connection.clientChain = chain;
        assertEquals(success ? KeeperException.Code.OK : KeeperException.Code.AUTHFAILED, provider.handleAuthentication(connection, null));
        return connection.getAuthInfo();
    }

    /** Example policy, not a built-in SPIFFE parser: retain full URI SANs and optionally the DN. */
    private static class UriIdentityProvider extends X509AuthenticationProvider {
        private final boolean includeDn;

        UriIdentityProvider(boolean includeDn) {
            super(X509IdentityMappingTest.trustManager, null);
            this.includeDn = includeDn;
        }

        @Override
        protected Collection<String> getClientIds(X509Certificate cert) throws CertificateException {
            List<String> identities = new ArrayList<>();
            if (includeDn) {
                identities.addAll(super.getClientIds(cert));
            }
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (Integer.valueOf(6).equals(san.get(0))) {
                        String uri = (String) san.get(1);
                        if (!isAbsoluteUri(uri)) {
                            throw new CertificateException("Invalid URI SAN");
                        }
                        identities.add("uri:" + uri);
                    }
                }
            }
            return identities;
        }

        @Override
        public boolean isValid(String id) {
            return id.startsWith("uri:") ? isAbsoluteUri(id.substring(4)) : super.isValid(id);
        }

        private static boolean isAbsoluteUri(String value) {
            try {
                return new URI(value).isAbsolute();
            } catch (URISyntaxException e) {
                return false;
            }
        }
    }
}
