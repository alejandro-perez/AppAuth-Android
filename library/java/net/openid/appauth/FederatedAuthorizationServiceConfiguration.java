/*
 * Copyright 2015 The AppAuth for Android Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openid.appauth;

import android.net.Uri;
import android.os.AsyncTask;
import android.support.annotation.NonNull;
import android.util.Log;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import net.openid.appauth.AuthorizationException.GeneralErrors;
import net.openid.appauth.connectivity.ConnectionBuilder;
import net.openid.appauth.internal.Logger;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static net.openid.appauth.Preconditions.checkNotNull;
import static org.geant.oidcfed.FederatedMetadataStatement.getFederatedConfiguration;

/**
 * Configuration details required to interact with an authorization service.
 */
public class FederatedAuthorizationServiceConfiguration extends AuthorizationServiceConfiguration {
    /**
     * Creates an service configuration for an OpenID Connect provider, based on its
     * {@link AuthorizationServiceDiscovery discovery document}.
     *
     * @param discoveryDoc The OpenID Connect discovery document which describes this service.
     */
    public FederatedAuthorizationServiceConfiguration(
            @NonNull AuthorizationServiceDiscovery discoveryDoc) {
        super(discoveryDoc);
    }

    /**
     * Fetch a AuthorizationServiceConfiguration from an OpenID Connect discovery URI.
     *
     * @param openIdConnectDiscoveryUri The OpenID Connect discovery URI
     * @param connectionBuilder The connection builder that is used to establish a connection
     *     to the resource server.
     * @param callback A callback to invoke upon completion
     * @param authorized_keys A JSONObject representing a JWKS with the authorized_keys for
     *                        federation support
     *
     * @see "OpenID Connect discovery 1.0
     * <https://openid.net/specs/openid-connect-discovery-1_0.html>"
     */
    public static void fetchFromUrl(
        @NonNull Uri openIdConnectDiscoveryUri,
        @NonNull RetrieveConfigurationCallback callback,
        @NonNull ConnectionBuilder connectionBuilder,
        @NonNull JSONObject authorized_keys) {
        checkNotNull(openIdConnectDiscoveryUri, "openIDConnectDiscoveryUri cannot be null");
        checkNotNull(callback, "callback cannot be null");
        checkNotNull(connectionBuilder, "connectionBuilder must not be null");
        checkNotNull(authorized_keys, "authorized_keys must not be null");
        new ConfigurationRetrievalAsyncTask(
            openIdConnectDiscoveryUri,
            connectionBuilder,
            authorized_keys,
            callback)
            .execute();
    }

    /**
     * ASyncTask that tries to retrieve the discover document and gives the callback with the
     * values retrieved from the discovery document. In case of retrieval error, the exception
     * is handed back to the callback.
     */
    private static class ConfigurationRetrievalAsyncTask
            extends AsyncTask<Void, Void, FederatedAuthorizationServiceConfiguration> {

        private Uri mUri;
        private ConnectionBuilder mConnectionBuilder;
        private RetrieveConfigurationCallback mCallback;
        private AuthorizationException mException;
        private JSONObject mAuthorizedKeys;

        ConfigurationRetrievalAsyncTask(
                Uri uri,
                ConnectionBuilder connectionBuilder,
                JSONObject authorized_keys,
                RetrieveConfigurationCallback callback) {
            mUri = uri;
            mConnectionBuilder = connectionBuilder;
            mCallback = callback;
            mAuthorizedKeys = authorized_keys;
            mException = null;
        }

        @Override
        protected FederatedAuthorizationServiceConfiguration doInBackground(Void... voids) {
            InputStream is = null;
            try {
                HttpURLConnection conn = mConnectionBuilder.openConnection(mUri);
                conn.setRequestMethod("GET");
                conn.setDoInput(true);
                conn.connect();

                is = conn.getInputStream();
                JSONObject json = new JSONObject(Utils.readInputStream(is));

                JSONObject mss = getFederatedConfiguration(json, this.mAuthorizedKeys);
                if (mss != null)
                    json = mss;

                AuthorizationServiceDiscovery discovery =
                        new AuthorizationServiceDiscovery(json);

                return new FederatedAuthorizationServiceConfiguration(discovery);
            } catch (IOException ex) {
                Logger.errorWithStack(ex, "Network error when retrieving discovery document");
                mException = AuthorizationException.fromTemplate(
                        GeneralErrors.NETWORK_ERROR,
                        ex);
            } catch (JSONException ex) {
                Logger.errorWithStack(ex, "Error parsing discovery document");
                mException = AuthorizationException.fromTemplate(
                        GeneralErrors.JSON_DESERIALIZATION_ERROR,
                        ex);
            } catch (AuthorizationServiceDiscovery.MissingArgumentException ex) {
                Logger.errorWithStack(ex, "Malformed discovery document");
                mException = AuthorizationException.fromTemplate(
                        GeneralErrors.INVALID_DISCOVERY_DOCUMENT,
                        ex);
            } finally {
                Utils.closeQuietly(is);
            }
            return null;
        }

        @Override
        protected void onPostExecute(FederatedAuthorizationServiceConfiguration configuration) {
            if (mException != null) {
                mCallback.onFetchConfigurationCompleted(null, mException);
            } else {
                mCallback.onFetchConfigurationCompleted(configuration, null);
            }
        }
    }
}
