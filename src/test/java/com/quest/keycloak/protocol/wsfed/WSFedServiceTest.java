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

package com.quest.keycloak.protocol.wsfed;

import com.quest.keycloak.common.wsfed.MockHelper;
import com.quest.keycloak.common.wsfed.TestHelpers;
import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.protocol.wsfed.builders.WSFedProtocolParameters;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.common.util.PemUtils;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.RealmsResource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.*;

import java.util.Arrays;
import java.util.HashSet;
import java.util.UUID;

import static com.quest.keycloak.common.wsfed.TestHelpers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class WSFedServiceTest {
    @Mock private EventBuilder event;
    @Mock private AuthenticationManager authManager;
    @Mock private AuthenticationManager.AuthResult authResult;
    //@Mock private Providers providers;
    //@Mock private SecurityContext securityContext;
    @Mock private HttpHeaders headers;
    @Mock private HttpRequest request;
    @Mock private HttpResponse response;
    @Mock private ClientConnection clientConnection;

    private MockHelper mockHelper;
    private WrappedWSFedService service;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        mockHelper = TestHelpers.getMockHelper().initializeMockValues();

        service = spy(new WrappedWSFedService(mockHelper.getRealm(), this.event));
        injectMocks(service);
    }

    protected class WrappedWSFedService extends WSFedService {
        public WrappedWSFedService(RealmModel realm, EventBuilder event) {
            super(realm, event);
        }

        public WrappedWSFedService setUriInfo(UriInfo uriInfo) {
            this.uriInfo = uriInfo;
            return this;
        }

        public WrappedWSFedService setHeaders(HttpHeaders headers) {
            this.headers = headers;
            return this;
        }

        public WrappedWSFedService setRequest(HttpRequest request) {
            this.request = request;
            return this;
        }

        public WrappedWSFedService setSession(KeycloakSession session) {
            this.session = session;
            return this;
        }

        public WrappedWSFedService setClientConnection(ClientConnection clientConnection) {
            this.clientConnection = clientConnection;
            return this;
        }
    }

    //@InjectMocks seems to have issues with the @Context fields. There are also some known issues with @InjectMocks and @Spy.
    //So instead inject manually.
    private void injectMocks(WrappedWSFedService service) throws Exception {
        doReturn(mockHelper.getUserSessionModel()).when(authResult).getSession();
        doReturn(authResult).when(service).authenticateIdentityCookie();

        service.setUriInfo(mockHelper.getUriInfo())
                .setHeaders(this.headers)
                .setRequest(this.request)
                .setSession(mockHelper.getSession())
                .setClientConnection(this.clientConnection);

        /*service.providers = this.providers;
        service.securityContext = this.securityContext;
        service.uriInfo = mockHelper.getUriInfo();
        service.headers = this.headers;
        service.request = this.request;
        service.response = this.response;
        service.session = mockHelper.getSession();
        service.clientConnection = this.clientConnection;*/
    }

    @Test
    public void testRedirectBinding() throws Exception {
        doReturn(null).when(service).handleWsFedRequest(eq(false));
        assertNull(service.redirectBinding());
        verify(service, times(1)).handleWsFedRequest(eq(false));
    }

    @Test
    public void testPostBinding() throws Exception {
        doReturn(null).when(service).handleWsFedRequest(eq(true));
        assertNull(service.postBinding());
        verify(service, times(1)).handleWsFedRequest(eq(true));
    }

    @Test
    public void testGetDescriptor() throws Exception {
        String descriptor = service.getDescriptor();
        Document doc = DocumentUtil.getDocument(descriptor);

        Element root = doc.getDocumentElement();
        assertEquals(RealmsResource.realmBaseUrl(mockHelper.getUriInfo()).build(mockHelper.getRealmName()).toString(), root.getAttribute("entityID"));

        WSFedNamespaceContext nsContext = new WSFedNamespaceContext("urn:oasis:names:tc:SAML:2.0:metadata");

        Node node = assertNode(doc, "/ns:EntityDescriptor/ns:RoleDescriptor/ns:KeyDescriptor/dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate", nsContext);
        assertEquals(PemUtils.encodeCertificate(mockHelper.getActiveKey().getCertificate()), node.getTextContent().trim());

        node = assertNode(doc, "/ns:EntityDescriptor/ns:RoleDescriptor/fed:SecurityTokenServiceEndpoint/wsa:EndpointReference/wsa:Address", nsContext);
        assertEquals(RealmsResource.protocolUrl(mockHelper.getUriInfo()).build(mockHelper.getRealmName(), WSFedLoginProtocol.LOGIN_PROTOCOL).toString(), node.getTextContent());

        node = assertNode(doc, "/ns:EntityDescriptor/ns:RoleDescriptor/fed:PassiveRequestorEndpoint/wsa:EndpointReference/wsa:Address", nsContext);
        assertEquals(RealmsResource.protocolUrl(mockHelper.getUriInfo()).build(mockHelper.getRealmName(), WSFedLoginProtocol.LOGIN_PROTOCOL).toString(), node.getTextContent());
    }

    @Test
    public void testBasicChecksNoSsl() throws Exception {
        //Default baseUri is https so we need to change the mocks for this test
        mockHelper = TestHelpers.getMockHelper();
        mockHelper.setBaseUri("http://dib.software.dell.com/auth").initializeMockValues();

        SslRequired ssl = SslRequired.ALL;
        doReturn(ssl).when(mockHelper.getRealm()).getSslRequired();

        service = spy(new WrappedWSFedService(mockHelper.getRealm(), this.event));
        injectMocks(service);

        assertNotNull(service.basicChecks(mock(WSFedProtocolParameters.class)));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.HTTPS_REQUIRED);
    }

    @Test
    public void testBasicChecksRealmDisabled() throws Exception {
        doReturn(false).when(mockHelper.getRealm()).isEnabled();
        assertNotNull(service.basicChecks(mock(WSFedProtocolParameters.class)));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.REALM_NOT_ENABLED);
    }

    @Test
    public void testBasicChecksMissingActionLoggingOut() throws Exception {
        WSFedProtocolParameters parameters = new WSFedProtocolParameters();
        parameters.setWsfed_realm("https://realm");
        doReturn(UserSessionModel.State.LOGGING_OUT).when(mockHelper.getUserSessionModel()).getState();

        assertNull(service.basicChecks(parameters));
        assertEquals(UserSessionModel.State.LOGGING_OUT.toString(), parameters.getWsfed_action());
    }

    @Test
    public void testBasicChecksMissingAction() throws Exception {
        WSFedProtocolParameters parameters = new WSFedProtocolParameters();
        parameters.setWsfed_realm("https://realm");
        doReturn(UserSessionModel.State.LOGGED_IN).when(mockHelper.getUserSessionModel()).getState();

        assertNotNull(service.basicChecks(parameters));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.INVALID_REQUEST);
    }

    @Test
    public void testBasicChecksMissingRealm() throws Exception {
        WSFedProtocolParameters parameters = new WSFedProtocolParameters();
        parameters.setWsfed_action(WSFedConstants.WSFED_SIGNIN_ACTION);

        assertNotNull(service.basicChecks(parameters));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.INVALID_REQUEST);
    }

    @Test
    public void testBasicChecksMissingRealmLoggingOut() throws Exception {
        WSFedProtocolParameters parameters = new WSFedProtocolParameters();
        parameters.setWsfed_action(WSFedConstants.WSFED_SIGNOUT_ACTION);

        doReturn("https://realm").when(mockHelper.getUserSessionModel()).getNote(eq(WSFedConstants.WSFED_REALM));

        assertNull(service.basicChecks(parameters));
        assertEquals("https://realm", parameters.getWsfed_realm());
    }

    @Test
    public void testBasicChecks() throws Exception {
        WSFedProtocolParameters parameters = new WSFedProtocolParameters();
        parameters.setWsfed_action(WSFedConstants.WSFED_SIGNIN_ACTION);
        parameters.setWsfed_realm("https://realm");

        assertNull(service.basicChecks(parameters));
    }

    @Test
    public void testIsSignout() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();

        params.setWsfed_action(WSFedConstants.WSFED_SIGNOUT_ACTION);
        assertTrue(service.isSignout(params));

        params.setWsfed_action(WSFedConstants.WSFED_SIGNOUT_CLEANUP_ACTION);
        assertTrue(service.isSignout(params));

        params.setWsfed_action(UserSessionModel.State.LOGGING_OUT.toString());
        assertTrue(service.isSignout(params));

        params.setWsfed_action(WSFedConstants.WSFED_SIGNIN_ACTION);
        assertFalse(service.isSignout(params));
    }

    @Test
    public void testClientChecksSignout() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();

        params.setWsfed_action(WSFedConstants.WSFED_SIGNOUT_ACTION);
        assertNull(service.clientChecks(mockHelper.getClient(), params));
    }

    @Test
    public void testClientChecksNullClient() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_action(WSFedConstants.WSFED_SIGNIN_ACTION);

        assertNotNull(service.clientChecks(null, params));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.UNKNOWN_LOGIN_REQUESTER);
    }

    @Test
    public void testClientChecksDisabledClient() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_action(WSFedConstants.WSFED_SIGNIN_ACTION);

        doReturn(false).when(mockHelper.getClient()).isEnabled();
        assertNotNull(service.clientChecks(mockHelper.getClient(), params));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.LOGIN_REQUESTER_NOT_ENABLED);
    }

    @Test
    public void testClientChecksBearerOnlyClient() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_action(WSFedConstants.WSFED_SIGNIN_ACTION);

        doReturn(true).when(mockHelper.getClient()).isBearerOnly();
        assertNotNull(service.clientChecks(mockHelper.getClient(), params));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.BEARER_ONLY);
    }

    @Test
    public void testClientChecks() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_action(WSFedConstants.WSFED_SIGNIN_ACTION);

        assertNull(service.clientChecks(mockHelper.getClient(), params));
        verify(mockHelper.getSession().getContext(), times(1)).setClient(eq(mockHelper.getClient()));
    }

    @Test
    public void testHandleWsFedRequestPostSignin() throws Exception {
        MultivaluedMap<String, String> params = new MultivaluedMapImpl<>();
        params.add(WSFedConstants.WSFED_REALM, mockHelper.getClientId());
        params.add(WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_SIGNIN_ACTION);

        doReturn(HttpMethod.POST).when(request).getHttpMethod();
        doReturn(params).when(request).getFormParameters();

        doReturn(null).when(service).handleLoginRequest(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()), eq(true));

        assertNull(service.handleWsFedRequest(true));
        verify(service, times(1)).handleLoginRequest(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()), eq(true));
    }

    @Test
    public void testHandleWsFedRequestGetSignin() throws Exception {
        MultivaluedMap<String, String> params = new MultivaluedMapImpl<>();
        params.add(WSFedConstants.WSFED_REALM, mockHelper.getClientId());
        params.add(WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_SIGNIN_ACTION);

        doReturn(HttpMethod.GET).when(request).getHttpMethod();
        doReturn(params).when(mockHelper.getUriInfo()).getQueryParameters(true);

        doReturn(null).when(service).handleLoginRequest(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()), eq(false));

        assertNull(service.handleWsFedRequest(false));
        verify(service, times(1)).handleLoginRequest(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()), eq(false));
    }

    @Test
    public void testHandleWsFedRequestAttributeAction() throws Exception {
        MultivaluedMap<String, String> params = new MultivaluedMapImpl<>();
        params.add(WSFedConstants.WSFED_REALM, mockHelper.getClientId());
        params.add(WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_ATTRIBUTE_ACTION);

        doReturn(HttpMethod.GET).when(request).getHttpMethod();
        doReturn(params).when(mockHelper.getUriInfo()).getQueryParameters(true);

        Response response = service.handleWsFedRequest(false);
        assertNotNull(response);
        assertEquals(501, response.getStatus());
    }

    @Test
    public void testHandleWsFedRequestSignoutAction() throws Exception {
        MultivaluedMap<String, String> params = new MultivaluedMapImpl<>();
        params.add(WSFedConstants.WSFED_REALM, mockHelper.getClientId());
        params.add(WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_SIGNOUT_ACTION);

        doReturn(HttpMethod.GET).when(request).getHttpMethod();
        doReturn(params).when(mockHelper.getUriInfo()).getQueryParameters(true);

        doReturn(null).when(service).handleLogoutRequest(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()));

        assertNull(service.handleWsFedRequest(false));
        verify(service, times(1)).handleLogoutRequest(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()));
    }

    @Test
    public void testHandleWsFedRequestSignoutCleanupAction() throws Exception {
        MultivaluedMap<String, String> params = new MultivaluedMapImpl<>();
        params.add(WSFedConstants.WSFED_REALM, mockHelper.getClientId());
        params.add(WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_SIGNOUT_CLEANUP_ACTION);

        doReturn(HttpMethod.GET).when(request).getHttpMethod();
        doReturn(params).when(mockHelper.getUriInfo()).getQueryParameters(true);

        doReturn(null).when(service).handleLogoutRequest(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()));

        assertNull(service.handleWsFedRequest(false));
        verify(service, times(1)).handleLogoutRequest(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()));
    }

    @Test
    public void testHandleWsFedRequestLoggingOutAction() throws Exception {
        MultivaluedMap<String, String> params = new MultivaluedMapImpl<>();
        params.add(WSFedConstants.WSFED_REALM, mockHelper.getClientId());
        params.add(WSFedConstants.WSFED_ACTION, UserSessionModel.State.LOGGING_OUT.toString());

        doReturn(HttpMethod.GET).when(request).getHttpMethod();
        doReturn(params).when(mockHelper.getUriInfo()).getQueryParameters(true);

        doReturn(null).when(service).handleLogoutResponse(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()));

        assertNull(service.handleWsFedRequest(false));
        verify(service, times(1)).handleLogoutResponse(any(WSFedProtocolParameters.class), eq(mockHelper.getClient()));
    }

    @Test
    public void testHandleWsFedRequestInvalidAction() throws Exception {
        MultivaluedMap<String, String> params = new MultivaluedMapImpl<>();
        params.add(WSFedConstants.WSFED_REALM, mockHelper.getClientId());
        params.add(WSFedConstants.WSFED_ACTION, "InvalidAction");

        doReturn(HttpMethod.GET).when(request).getHttpMethod();
        doReturn(params).when(mockHelper.getUriInfo()).getQueryParameters(true);

        assertNotNull(service.handleWsFedRequest(false));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.INVALID_REQUEST);
    }

    @Test
    public void testHandleLogoutResponseNoAuthResult() throws Exception {
        doReturn(null).when(service).authenticateIdentityCookie();

        assertNotNull(service.handleLogoutResponse(null, null));
        verify(event, times(1)).error(Errors.INVALID_TOKEN);
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.INVALID_REQUEST);
    }

    @Test
    public void testHandleLogoutResponseInvalidState() throws Exception {
        doReturn(UserSessionModel.State.LOGGING_IN).when(mockHelper.getUserSessionModel()).getState();

        assertNotNull(service.handleLogoutResponse(null, null));
        verify(event, times(1)).error(Errors.INVALID_SAML_LOGOUT_RESPONSE);
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.INVALID_REQUEST);
    }

    @Test
    public void testHandleLogoutResponse() throws Exception {
        doReturn(UserSessionModel.State.LOGGING_OUT).when(mockHelper.getUserSessionModel()).getState();

        try {
            //authManager.browserLogout isn't mocked and so it will throw a NPE. That's ok because we can still validate we got there
            service.handleLogoutResponse(null, null);
            fail("Expected NPE");
        }
        catch(NullPointerException ex) {
        }

        //This is in browserLogout
        verify(mockHelper.getUserSessionModel(), times(2)).getUser();
    }

    @Test
    public void testHandleLogoutRequestNoClientOrReply() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();

        assertNotNull(service.handleLogoutRequest(params, null));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.INVALID_REQUEST);
    }

    @Test
    public void testHandleLogoutRequestReplyAddress() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_reply("https://redirectUri");
        params.setWsfed_context("context");

        doReturn(new HashSet<>(Arrays.asList(params.getWsfed_reply()))).when(mockHelper.getClient()).getRedirectUris();
        doReturn(null).when(service).authenticateIdentityCookie();

        Response response = service.handleLogoutRequest(params, mockHelper.getClient());
        Document doc = responseToDocument(response);

        assertFormAction(doc, HttpMethod.GET, params.getWsfed_reply());
        assertInputNode(doc, WSFedConstants.WSFED_CONTEXT, params.getWsfed_context());
    }

    @Test
    public void testHandleLogoutRequestReplyAddressNoClient() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_reply("https://redirectUri");
        params.setWsfed_context("context");

        doReturn(new HashSet<>(Arrays.asList(params.getWsfed_reply()))).when(mockHelper.getClient()).getRedirectUris();
        doReturn(null).when(service).authenticateIdentityCookie();
        doReturn(Arrays.asList(mockHelper.getClient())).when(mockHelper.getRealm()).getClients();

        Response response = service.handleLogoutRequest(params, null);
        Document doc = responseToDocument(response);

        assertFormAction(doc, HttpMethod.GET, params.getWsfed_reply());
        assertInputNode(doc, WSFedConstants.WSFED_CONTEXT, params.getWsfed_context());
    }

    @Test
    public void testHandleLogoutRequest() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_reply("https://redirectUri");
        params.setWsfed_context("context");

        doReturn(new HashSet<>(Arrays.asList(params.getWsfed_reply()))).when(mockHelper.getClient()).getRedirectUris();
        doReturn(Arrays.asList(mockHelper.getClientSessionModel())).when(mockHelper.getUserSessionModel()).getClientSessions();
        doReturn(mockHelper.getClient()).when(mockHelper.getClientSessionModel()).getClient();

        try {
            //authManager.browserLogout isn't mocked and so it will throw a NPE. That's ok because we can still validate we got there
            service.handleLogoutRequest(params, mockHelper.getClient());
            fail("Expected NPE");
        }
        catch(NullPointerException ex) {
        }

        verify(mockHelper.getUserSessionModel(), times(1)).setNote(eq(WSFedLoginProtocol.WSFED_LOGOUT_BINDING_URI), eq(params.getWsfed_reply()));
        verify(mockHelper.getUserSessionModel(), times(1)).setNote(eq(WSFedLoginProtocol.WSFED_CONTEXT), eq(params.getWsfed_context()));
        verify(mockHelper.getUserSessionModel(), times(1)).setNote(eq(AuthenticationManager.KEYCLOAK_LOGOUT_PROTOCOL), eq(WSFedLoginProtocol.LOGIN_PROTOCOL));

        verify(mockHelper.getClientSessionModel(), times(1)).setAction(eq(ClientSessionModel.Action.LOGGED_OUT.name()));

        //This is in browserLogout
        verify(mockHelper.getUserSessionModel(), times(2)).getUser();
    }

    @Test
    public void testHandleLoginRequestInvalidRedirect() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_reply("https://redirectUri");
        params.setWsfed_context("context");

        //doReturn(new HashSet<>(Arrays.asList(params.getWsfed_reply()))).when(mockHelper.getClient()).getRedirectUris();
        assertNotNull(service.handleLoginRequest(params, mockHelper.getClient(), false));
        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.INVALID_REDIRECT_URI);
    }

    @Test
    public void testHandleLoginRequestInvalidNonFormAuth() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_reply("https://redirectUri");
        params.setWsfed_context("context");

        doReturn(new HashSet<>(Arrays.asList(params.getWsfed_reply()))).when(mockHelper.getClient()).getRedirectUris();

        ClientSessionModel clientSession = mock(ClientSessionModel.class);
        UserSessionProvider provider = mockHelper.getSession().sessions();
        doReturn(clientSession).when(provider).createClientSession(mockHelper.getRealm(), mockHelper.getClient());

        Response errorResponse = mock(Response.class);
        doReturn(errorResponse).when(service).newBrowserAuthentication(eq(clientSession), eq(false), eq(false));

        Response response = service.handleLoginRequest(params, mockHelper.getClient(), false);
        assertEquals(errorResponse, response);

        verify(clientSession, times(1)).setAuthMethod(eq(WSFedLoginProtocol.LOGIN_PROTOCOL));
        verify(clientSession, times(1)).setRedirectUri(eq(params.getWsfed_reply()));
        verify(clientSession, times(1)).setAction(eq(ClientSessionModel.Action.AUTHENTICATE.name()));
        verify(clientSession, times(1)).setNote(eq(WSFedConstants.WSFED_CONTEXT), eq(params.getWsfed_context()));
        String issuer = RealmsResource.realmBaseUrl(mockHelper.getUriInfo()).build(mockHelper.getRealmName()).toString();
        verify(clientSession, times(1)).setNote(eq(OIDCLoginProtocol.ISSUER), eq(issuer));
    }

    @Test
    public void testHandleLoginRequest() throws Exception {
        WSFedProtocolParameters params = new WSFedProtocolParameters();
        params.setWsfed_reply("https://redirectUri");
        params.setWsfed_context("context");

        doReturn(new HashSet<>(Arrays.asList(params.getWsfed_reply()))).when(mockHelper.getClient()).getRedirectUris();

        ClientSessionModel clientSession = mock(ClientSessionModel.class);
        when(clientSession.getId()).thenReturn(UUID.randomUUID().toString());
        when(clientSession.getClient()).thenReturn(mockHelper.getClient());

        UserSessionProvider provider = mockHelper.getSession().sessions();
        doReturn(clientSession).when(provider).createClientSession(mockHelper.getRealm(), mockHelper.getClient());

        AuthenticationFlowModel flow = mock(AuthenticationFlowModel.class);
        doReturn(UUID.randomUUID().toString()).when(flow).getId();
        doReturn(flow).when(mockHelper.getRealm()).getBrowserFlow();

        doReturn(SslRequired.EXTERNAL).when(mockHelper.getRealm()).getSslRequired();
        doReturn(new MultivaluedMapImpl<String, Object>()).when(response).getOutputHeaders();

        ResteasyProviderFactory.pushContext(HttpResponse.class, response);

        //This won't complete but if we get the correct error page it means that we have hit processor.authenticate which is good enough for us in this test
        Response response = service.handleLoginRequest(params, mockHelper.getClient(), false);
        assertNotNull(response);

        assertErrorPage(mockHelper.getLoginFormsProvider(), Messages.INVALID_CODE);
    }
}