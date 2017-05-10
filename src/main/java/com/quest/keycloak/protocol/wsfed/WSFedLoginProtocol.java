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

import java.io.InputStream;
import java.security.KeyPair;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.common.wsfed.builders.WSFedResponseBuilder;
import com.quest.keycloak.protocol.wsfed.builders.WSFedSAML2AssertionTypeBuilder;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;

import com.quest.keycloak.protocol.wsfed.builders.RequestSecurityTokenResponseBuilder;
import com.quest.keycloak.protocol.wsfed.builders.WSFedOIDCAccessTokenBuilder;

/**
 * Created on 5/19/15.
 */
public class WSFedLoginProtocol implements LoginProtocol {
    protected static final Logger logger = Logger.getLogger(WSFedLoginProtocol.class);
    public static final String LOGIN_PROTOCOL = "wsfed";

    public static final String WSFED_JWT = "wsfed.jwt";
    public static final String WSFED_X5T = "wsfed.x5t";
    public static final String WSFED_LOGOUT_BINDING_URI = "WSFED_LOGOUT_BINDING_URI";
    public static final String WSFED_CONTEXT = "WSFED_CONTEXT";

    private KeycloakSession session;

    private RealmModel realm;

    protected UriInfo uriInfo;

    protected HttpHeaders headers;

    private EventBuilder event;

    @Override
    public LoginProtocol setSession(KeycloakSession session) {
        this.session = session;
        return this;
    }

    @Override
    public LoginProtocol setRealm(RealmModel realm) {
        this.realm = realm;
        return this;
    }

    @Override
    public LoginProtocol setHttpHeaders(HttpHeaders headers) {
        this.headers = headers;
        return this;
    }

    @Override
    public LoginProtocol setUriInfo(UriInfo uriInfo) {
        this.uriInfo = uriInfo;
        return this;
    }

    @Override
    public LoginProtocol setEventBuilder(EventBuilder event) {
        this.event = event;
        return this;
    }

    @Override
    public Response sendError(ClientSessionModel clientSession, Error error) {
        //Replaced cancelLogin
        if(error == Error.CANCELLED_BY_USER) {
            return getErrorResponse(clientSession, WSFedConstants.WSFED_ERROR_NOTSIGNEDIN);
        }

        //TODO: This is new figure out what to do here.
        return getErrorResponse(clientSession, Messages.FAILED_TO_PROCESS_RESPONSE);
    }

    protected Response getErrorResponse(ClientSessionModel clientSession, String status) {
        /* TODO: Does WS-Fed support error response like SAML (I think it does)
        String redirect = clientSession.getRedirectUri();
        UriBuilder redirectUri = UriBuilder.fromUri(redirect).queryParam(OAuth2Constants.ERROR, "access_denied");
        if (state != null) {
            redirectUri.queryParam(OAuth2Constants.STATE, state);
        }
        return Response.status(302).location(redirectUri.build()).build();*/

        return ErrorPage.error(session, status);
    }

    @Override
    public Response authenticated(UserSessionModel userSession, ClientSessionCode accessCode) {
        ClientSessionModel clientSession = accessCode.getClientSession();
        ClientModel client = clientSession.getClient();
        String context = clientSession.getNote(WSFedConstants.WSFED_CONTEXT);
        userSession.setNote(WSFedConstants.WSFED_REALM, client.getClientId());

        try {
            RequestSecurityTokenResponseBuilder builder = new RequestSecurityTokenResponseBuilder();
            KeyManager keyManager = session.keys();
            KeyManager.ActiveRsaKey activeKey = keyManager.getActiveRsaKey(realm);

            builder.setRealm(clientSession.getClient().getClientId())
                    .setAction(WSFedConstants.WSFED_SIGNIN_ACTION)
                    .setDestination(clientSession.getRedirectUri())
                    .setContext(context)
                    .setTokenExpiration(realm.getAccessTokenLifespan())
                    .setRequestIssuer(clientSession.getClient().getClientId())
                    .setSigningKeyPair(new KeyPair(activeKey.getPublicKey(), activeKey.getPrivateKey()))
                    .setSigningCertificate(activeKey.getCertificate())
                    .setSigningKeyPairId(activeKey.getKid());

            if (useJwt(client)) {
                WSFedOIDCAccessTokenBuilder oidcBuilder = new WSFedOIDCAccessTokenBuilder();
                oidcBuilder.setSession(session)
                            .setUserSession(userSession)
                            .setAccessCode(accessCode)
                            .setClient(client)
                            .setClientSession(clientSession)
                            .setRealm(realm)
                            .setX5tIncluded(isX5tIncluded(client));

                String token = oidcBuilder.build();
                builder.setJwt(token);
            } else {
                //if client wants SAML
                WSFedSAML2AssertionTypeBuilder samlBuilder = new WSFedSAML2AssertionTypeBuilder();
                samlBuilder.setRealm(realm)
                            .setUriInfo(uriInfo)
                            .setAccessCode(accessCode)
                            .setClientSession(clientSession)
                            .setUserSession(userSession)
                            .setSession(session);

                AssertionType token = samlBuilder.build();
                builder.setSamlToken(token);
            }

            return builder.buildResponse();
        } catch (Exception e) {
            logger.error("failed", e);
            return ErrorPage.error(session, Messages.FAILED_TO_PROCESS_RESPONSE);
        }
    }

    protected boolean useJwt(ClientModel client) {
        return Boolean.parseBoolean(client.getAttribute(WSFED_JWT));
    }

    protected boolean isX5tIncluded(ClientModel client) {
        return Boolean.parseBoolean(client.getAttribute(WSFED_X5T));
    }

    @Override
    public void backchannelLogout(UserSessionModel userSession, ClientSessionModel clientSession) {
        logger.debug("backchannelLogout");
        ClientModel client = clientSession.getClient();
        String redirectUri = null;
        if (client.getRedirectUris().size() > 0) {
        	redirectUri = client.getRedirectUris().iterator().next();
        }
        String logoutUrl = RedirectUtils.verifyRedirectUri(uriInfo, redirectUri, realm, client);
        if (logoutUrl == null) {
            logger.warn("Can't do backchannel logout. No SingleLogoutService POST Binding registered for client: " + client.getClientId());
            return;
        }

        //Basically the same as SAML only we don't need to send an actual LogoutRequest. Just need to send the signoutcleanup1.0 action.
        HttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();

        for (int i = 0; i < 2; i++) { // follow redirects once
            try {
                URIBuilder builder = new URIBuilder(logoutUrl);
                builder.addParameter(WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_SIGNOUT_CLEANUP_ACTION);
                builder.addParameter(WSFedConstants.WSFED_REALM, client.getClientId());
                HttpGet get = new HttpGet(builder.build());
                HttpResponse response = httpClient.execute(get);
                try {
                    int status = response.getStatusLine().getStatusCode();
                    if (status == 302  && !logoutUrl.endsWith("/")) {
                        String redirect = response.getFirstHeader(HttpHeaders.LOCATION).getValue();
                        String withSlash = logoutUrl + "/";
                        if (withSlash.equals(redirect)) {
                            logoutUrl = withSlash;
                            continue;
                        }
                    }
                } finally {
                    HttpEntity entity = response.getEntity();
                    if (entity != null) {
                        InputStream is = entity.getContent();
                        if (is != null) is.close();
                    }

                }
            } catch (Exception e) {
                logger.warn("failed to send ws-fed logout to RP", e);
            }
            break;
        }
    }

    @Override
    public Response frontchannelLogout(UserSessionModel userSession, ClientSessionModel clientSession) {
        logger.debug("frontchannelLogout");
        ClientModel client = clientSession.getClient();
        String redirectUri = null;
        if (!client.getRedirectUris().isEmpty()) {
        	redirectUri = client.getRedirectUris().iterator().next();
        }
        String logoutUrl = RedirectUtils.verifyRedirectUri(uriInfo, redirectUri, realm, client);
        if (logoutUrl == null) {
            logger.error("Can't finish WS-Fed logout as there is no logout binding set. Has the redirect URI being used been added to the valid redirect URIs in the client?");
            return ErrorPage.error(session, Messages.FAILED_LOGOUT);
        }

        WSFedResponseBuilder builder = new WSFedResponseBuilder();
        builder.setMethod(HttpMethod.GET)
                .setAction(WSFedConstants.WSFED_SIGNOUT_CLEANUP_ACTION)
                .setReplyTo(getEndpoint(uriInfo, realm))
                .setDestination(logoutUrl);

        return builder.buildResponse(null);
    }

    @Override
    public Response finishLogout(UserSessionModel userSession) {
        logger.debug("finishLogout");
        String logoutUrl = userSession.getNote(WSFED_LOGOUT_BINDING_URI);
        if (logoutUrl == null) {
            logger.error("Can't finish WS-Fed logout as there is no logout binding set. Has the redirect URI being used been added to the valid redirect URIs in the client?");
            return ErrorPage.error(session, Messages.FAILED_LOGOUT);
        }

        WSFedResponseBuilder builder = new WSFedResponseBuilder();
        builder.setMethod(HttpMethod.GET)
                .setContext(userSession.getNote(WSFED_CONTEXT))
                .setDestination(logoutUrl);

        return builder.buildResponse(null);
    }

    @Override
    public void close() {

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean requireReauthentication(UserSessionModel userSession, ClientSessionModel clientSession) {
    	return false;
    }

    protected String getEndpoint(UriInfo uriInfo, RealmModel realm) {
        return uriInfo.getBaseUriBuilder()
                .path("realms").path(realm.getName())
                .path("protocol")
                .path(LOGIN_PROTOCOL)
                .build().toString();
    }
}
