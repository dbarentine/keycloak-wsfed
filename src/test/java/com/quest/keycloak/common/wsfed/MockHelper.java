/*
 * Copyright (C) 2015 Dell, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.quest.keycloak.common.wsfed;

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.keycloak.common.util.CertificateUtils;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeyManager.ActiveHmacKey;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.storage.UserStorageManager;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class MockHelper {
    private String baseUri = null;

    private String clientId = null;
    private Map<String, String> clientAttributes = new HashMap<>();
    private Map<String, String> clientSessionNotes = new HashMap<>();

    private String userName = null;
    private String email = null;

    private String realmName = null;
    private int accessCodeLifespan = 0;
    private int accessTokenLifespan = 0;

    private Map<ProtocolMapperModel, ProtocolMapper> protocolMappers = new HashMap<>();

    @Mock
    private UriInfo uriInfo;
    @Mock
    private RealmModel realm;
    @Mock
    private ClientModel client;
    @Mock
    private UserModel user;
    @Mock
    private KeyManager keyManager;
    @Mock
    private KeyManager.ActiveRsaKey activeKey;

    @Mock
    private LoginFormsProvider loginFormsProvider;
    @Mock
    private KeycloakSession session;
    @Mock
    private KeycloakSessionFactory sessionFactory;
    @Mock
    private ClientSessionModel clientSessionModel;
    @Mock
    private ClientSessionCode accessCode;
    @Mock
    private UserSessionModel userSessionModel;

    public MockHelper() {
        resetMocks();
    }

    public void resetMocks() {
        MockitoAnnotations.initMocks(this);
    }

    /**
     * Initialize the defaults based on field values. If you don't like the defaults they can be changed by using reset(mockClass) and then configure it however you want
     */
    public MockHelper initializeMockValues() {
        initializeSessionMock();
        initializeUriInfo();
        initializeRealmMock();
        initializeClientModelMock();
        intializeUserModelMock();
        intializeLoginFormsProviderMock();
        intializeKeycloakSessionFactoryMock();
        intializeKeycloakSessionMock();
        intializeClientSessionModelMock();
        initializeClientSessionCodeMock();
        intializeUserSessionModelMock();
        return this;
    }

    protected void initializeSessionMock(){
        when(session.keys()).thenReturn(keyManager);

    }
    protected void initializeUriInfo() {
        //We have to use thenAnswer so that the UriBuilder gets created on each call vs at mock time.
        when(getUriInfo().getBaseUriBuilder()).
                thenAnswer(new Answer<UriBuilder>() {
                    public UriBuilder answer(InvocationOnMock invocation) {
                        return UriBuilder.fromUri(getBaseUri());
                    }
                });

        URI baseUri = getUriInfo().getBaseUriBuilder().build();
        when(getUriInfo().getBaseUri()).thenReturn(baseUri);
    }

    protected void initializeRealmMock() {
        when(getRealm().getName()).thenReturn(getRealmName());
        when(getRealm().isEnabled()).thenReturn(true);
        when(getRealm().getAccessCodeLifespan()).thenReturn(getAccessCodeLifespan());
        when(getRealm().getAccessTokenLifespan()).thenReturn(getAccessTokenLifespan());
        generateActiveRealmKeys(keyManager, activeKey, realm);
    }

    public static void generateActiveRealmKeys(KeyManager keyManager, KeyManager.ActiveRsaKey activeKey, RealmModel realm){
    	if (keyManager.getActiveRsaKey(realm) != null){
            return;
        }
        KeyPair keyPair = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        X509Certificate certificate = null;
        try {
            certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, realm.getName());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        SecretKey secret = new SecretKeySpec("junit".getBytes(), "HmacSHA256");
        ActiveHmacKey activeHmacKey = new ActiveHmacKey(UUID.randomUUID().toString(), secret);
        when(keyManager.getActiveHmacKey(eq(realm))).thenReturn(activeHmacKey);
        when(keyManager.getActiveRsaKey(eq(realm))).thenReturn(activeKey);
        when(activeKey.getPublicKey()).thenReturn(keyPair.getPublic());
        when(activeKey.getPrivateKey()).thenReturn(keyPair.getPrivate());
        when(activeKey.getCertificate()).thenReturn(certificate);
        when(activeKey.getKid()).thenReturn(UUID.randomUUID().toString());

    }

    protected void initializeClientModelMock() {
        when(getClient().getId()).thenReturn(UUID.randomUUID().toString());
        when(getClient().getClientId()).thenReturn(getClientId());
        when(getClient().isEnabled()).thenReturn(true);

        for(Map.Entry<String, String> entry : getClientAttributes().entrySet()) {
            when(getClient().getAttribute(entry.getKey())).thenReturn(entry.getValue());
        }

        when(getClient().getProtocolMapperById(anyString())).thenAnswer(new Answer<ProtocolMapperModel>() {
            @Override
            public ProtocolMapperModel answer(InvocationOnMock invocation) throws Throwable {
                String id = (String) invocation.getArguments()[0];

                for (ProtocolMapperModel mm : getProtocolMappers().keySet()) {
                    if (mm.getId().equals(id)) {
                        return mm;
                    }
                }

                return null;
            }
        });

        when(realm.getClientByClientId(getClientId())).thenReturn(getClient());
    }

    protected void intializeUserModelMock() {
        when(getUser().getId()).thenReturn(UUID.randomUUID().toString());
        when(getUser().getUsername()).thenReturn(getUserName());
        when(getUser().getEmail()).thenReturn(getEmail());
    }

    protected void intializeLoginFormsProviderMock() {
        when(getLoginFormsProvider().setError(anyString())).thenReturn(getLoginFormsProvider());
        when(getLoginFormsProvider().createErrorPage()).thenReturn(mock(Response.class));
    }

    protected void intializeKeycloakSessionMock() {
        when(getSession().getProvider(LoginFormsProvider.class)).thenReturn(getLoginFormsProvider());
        when(getSession().getKeycloakSessionFactory()).thenReturn(getSessionFactory());
        when(getSession().users()).thenReturn(mock(UserStorageManager.class));
        when(getSession().users().getUserById(user.getId(), realm)).thenReturn(user);

        when(getSession().sessions()).thenReturn(mock(UserSessionProvider.class));
        when(getSession().sessions().getUserSessionByBrokerSessionId(realm, userSessionModel.getBrokerSessionId())).thenReturn(userSessionModel);
        when(getSession().sessions().getUserSessionByBrokerUserId(realm, getUser().getId())).thenReturn(Arrays.asList(userSessionModel));

        when(getSession().getContext()).thenReturn(mock(KeycloakContext.class));
    }

    protected void intializeKeycloakSessionFactoryMock() {
        for(Map.Entry<ProtocolMapperModel, ProtocolMapper> mapper : getProtocolMappers().entrySet()) {
            when(getSessionFactory().getProviderFactory(ProtocolMapper.class, mapper.getKey().getProtocolMapper())).thenReturn(mapper.getValue());
        }
    }

    protected void intializeClientSessionModelMock() {
        when(getClientSessionModel().getId()).thenReturn(UUID.randomUUID().toString());
        when(getClientSessionModel().getClient()).thenReturn(getClient());
        when(getClientSessionModel().getRedirectUri()).thenReturn(getClientId());

        for(Map.Entry<String, String> entry : getClientSessionNotes().entrySet()) {
            when(getClientSessionModel().getNote(entry.getKey())).thenReturn(entry.getValue());
        }

        Set<String> pm = new HashSet<>();
        for(Map.Entry<ProtocolMapperModel, ProtocolMapper> mapper : getProtocolMappers().entrySet()) {
            pm.add(mapper.getKey().getId());
        }

        when(getClientSessionModel().getProtocolMappers()).thenReturn(pm);
    }

    protected void initializeClientSessionCodeMock() {
        when(getAccessCode().getClientSession()).thenReturn(getClientSessionModel());
        when(getAccessCode().getRequestedProtocolMappers()).thenReturn(getProtocolMappers().keySet());
    }

    protected void intializeUserSessionModelMock() {
        when(getUserSessionModel().getId()).thenReturn(UUID.randomUUID().toString());
        when(getUserSessionModel().getBrokerSessionId()).thenReturn(UUID.randomUUID().toString());
        when(getUserSessionModel().getUser()).thenReturn(getUser());
        doReturn(getUser().getId()).when(getUserSessionModel()).getBrokerUserId();
    }

    public String getBaseUri() {
        return baseUri;
    }

    public MockHelper setBaseUri(String baseUri) {
        this.baseUri = baseUri;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public MockHelper setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public Map<String, String> getClientAttributes() {
        return clientAttributes;
    }

    public MockHelper setClientAttributes(Map<String, String> clientAttributes) {
        this.clientAttributes = clientAttributes;
        return this;
    }

    public Map<String, String> getClientSessionNotes() {
        return clientSessionNotes;
    }

    public MockHelper setClientSessionNotes(Map<String, String> clientSessionNotes) {
        this.clientSessionNotes = clientSessionNotes;
        return this;
    }

    public String getUserName() {
        return userName;
    }

    public MockHelper setUserName(String userName) {
        this.userName = userName;
        return this;
    }

    public String getEmail() {
        return email;
    }

    public MockHelper setEmail(String email) {
        this.email = email;
        return this;
    }

    public String getRealmName() {
        return realmName;
    }

    public MockHelper setRealmName(String realmName) {
        this.realmName = realmName;
        return this;
    }

    public int getAccessCodeLifespan() {
        return accessCodeLifespan;
    }

    public MockHelper setAccessCodeLifespan(int accessCodeLifespan) {
        this.accessCodeLifespan = accessCodeLifespan;
        return this;
    }

    public int getAccessTokenLifespan() {
        return accessTokenLifespan;
    }

    public MockHelper setAccessTokenLifespan(int accessTokenLifespan) {
        this.accessTokenLifespan = accessTokenLifespan;
        return this;
    }

    public UriInfo getUriInfo() {
        return uriInfo;
    }

    public MockHelper setUriInfo(UriInfo uriInfo) {
        this.uriInfo = uriInfo;
        return this;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public MockHelper setRealm(RealmModel realm) {
        this.realm = realm;
        return this;
    }

    public ClientModel getClient() {
        return client;
    }

    public MockHelper setClient(ClientModel client) {
        this.client = client;
        return this;
    }

    public UserModel getUser() {
        return user;
    }

    public MockHelper setUser(UserModel user) {
        this.user = user;
        return this;
    }

    public LoginFormsProvider getLoginFormsProvider() {
        return loginFormsProvider;
    }

    public MockHelper setLoginFormsProvider(LoginFormsProvider loginFormsProvider) {
        this.loginFormsProvider = loginFormsProvider;
        return this;
    }

    public KeycloakSession getSession() {
        return session;
    }

    public MockHelper setSessionFactory(KeycloakSessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
        return this;
    }

    public KeycloakSessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public MockHelper setSession(KeycloakSession session) {
        this.session = session;
        return this;
    }

    public ClientSessionModel getClientSessionModel() {
        return clientSessionModel;
    }

    public MockHelper setClientSessionModel(ClientSessionModel clientSessionModel) {
        this.clientSessionModel = clientSessionModel;
        return this;
    }

    public ClientSessionCode getAccessCode() {
        return accessCode;
    }

    public MockHelper setAccessCode(ClientSessionCode accessCode) {
        this.accessCode = accessCode;
        return this;
    }

    public UserSessionModel getUserSessionModel() {
        return userSessionModel;
    }

    public MockHelper setUserSessionModel(UserSessionModel userSessionModel) {
        this.userSessionModel = userSessionModel;
        return this;
    }

    public Map<ProtocolMapperModel, ProtocolMapper> getProtocolMappers() {
        return protocolMappers;
    }

    public void setProtocolMappers(Map<ProtocolMapperModel, ProtocolMapper> protocolMappers) {
        this.protocolMappers = protocolMappers;
    }

    public KeyManager.ActiveRsaKey getActiveKey() {
        return activeKey;
    }

    public KeyManager getKeyManager() {
        return keyManager;
    }
}
