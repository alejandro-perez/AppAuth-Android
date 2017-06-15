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

import static net.openid.appauth.Preconditions.checkNotNull;

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

        /**
         * Indicates whether an object is a subset of another one, according to the OIDC Federation
         * draft.
         * @param obj1 One object.
         * @param obj2 Another object.
         * @return True if obj1 is a subset of obj2. False otherwise.
         * @throws JSONException when the objects have an unexpected type.
         */
        private boolean is_subset(Object obj1, Object obj2) throws JSONException {
            if (!obj1.getClass().equals(obj2.getClass()))
                return false;
            else if (obj1 instanceof String)
                return obj1.equals(obj2);
            else if (obj1 instanceof Integer)
                return (Integer) obj1 <= (Integer) obj2;
            else if (obj1 instanceof Double)
                return (Double) obj1 <= (Double) obj2;
            else if (obj1 instanceof Long)
                return (Long) obj1 <= (Long) obj2;
            else if (obj1 instanceof Boolean)
                return obj1 == obj2;
            else if (obj1 instanceof JSONArray){
                JSONArray list1 = (JSONArray) obj1;
                JSONArray list2 = (JSONArray) obj2;
                for (int i=0; i<list1.length(); i++){
                    boolean found = false;
                    for (int j=0; j<list2.length(); j++){
                        if (list1.get(i).equals(list2.get(j))) {
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                        return false;
                }
                return true;
            }
            else if (obj1 instanceof JSONObject){
                JSONObject jobj1 = (JSONObject) obj1;
                JSONObject jobj2 = (JSONObject) obj2;
                for(Iterator<String> iter = jobj1.keys(); iter.hasNext();) {
                    String key = iter.next();
                    if (!jobj2.has(key) || !is_subset(jobj1.get(key), jobj2.get(key)))
                        return false;
                }
                return true;
            }
            else
                throw new JSONException("Unexpected JSON class: " + obj1.getClass().toString());
        }

        /**
         * Flatten two metadata statements into one, following the rules from the OIDC federation draft.
         * @param upper MS (n)
         * @param lower MS(n-1)
         * @return A flattened version of both statements.
         * @throws JSONException when upper MS tries to overwrite lower MS breaking the policies
         * from the OIDC federation draft.
         */
        private JSONObject flatten(JSONObject upper, JSONObject lower) throws JSONException {
            String[] use_lower = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"};
            String[] use_upper = {"signing_keys", "signing_keys_uri", "metadata_statement_uris", "kid",
                "metadata_statements", "usage"};
            // result starts as a copy of lower MS
            JSONObject flattened = new JSONObject(lower.toString());

            // then iterate over upper claims/keys
            for(Iterator<String> iter = upper.keys(); iter.hasNext();) {
                String claim_name = iter.next();

                // if the claim is marked as "use_lower", just ignore it as we will use lower's one
                if (Arrays.asList(use_lower).contains(claim_name))
                    continue;

                // if the claim does not exist on lower, or it is marked as "use_upper", or is a
                // subset of lower, then use upper's one
                if (lower.opt(claim_name) == null
                    || Arrays.asList(use_upper).contains(claim_name)
                    || is_subset(upper.get(claim_name), lower.get(claim_name))) {
                    flattened.put(claim_name, upper.get(claim_name));
                }

                // else, there is a policy breach that needs to be reported
                else {
                    throw new JSONException("Policy breach with claim: " + claim_name
                        + ". Lower value=" + lower.get(claim_name)
                        + ". Upper value=" + upper.get(claim_name));
                }
            }
            return flattened;
        }

        /**
         * Verifies the signature of a JWT using the indicated keys.
         * @param signedJWT Signed JWT
         * @param keys Keys that can be used to verify the token
         * @throws BadJOSEException when the JWT is not valid
         * @throws JOSEException when the signature cannot be validated
         */
        private void verify_signature(SignedJWT signedJWT, JWKSet keys) throws BadJOSEException, JOSEException {
            // TODO: I might want to change this to having a boolean return
            ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
            JWSKeySelector keySelector = new JWSVerificationKeySelector(signedJWT.getHeader().getAlgorithm(),
                new ImmutableJWKSet(keys));
            DefaultJWTClaimsVerifier cverifier = new DefaultJWTClaimsVerifier();
            // allow some clock skew as Roland's examples are somewhat static
            cverifier.setMaxClockSkew(5000000);
            jwtProcessor.setJWTClaimsSetVerifier(cverifier);
            jwtProcessor.setJWSKeySelector(keySelector);
            jwtProcessor.process(signedJWT, null);
        }

        /**
         * Collects inner metadata statements built upon the contents of
         *      the "metadata_statements" or "metadata_statement_uris" claims,
         *      including simple verifications such as both of them cannot appear at the same time.
         * @param payload Metadata statement containing inner metadata statements
         * @return A JSONArray with the list of inner metadata statements
         * @throws JSONException when "metadata_statements" and "metadata_statement_uris" appear at
         *      the same time
         * @throws IOException when a "metadata_statement_uris" key cannot be downloaded
         */
        private JSONArray get_metadata_statements(JSONObject payload) throws JSONException, IOException {
            JSONArray msl = payload.optJSONArray("metadata_statements");
            JSONObject ms_uris = payload.optJSONObject("metadata_statement_uris");

            // if there is a "metadata_statements" claim, just return it as it already has the
            // format we want
            if (msl != null){
                // If there is a "metadata_statement_uris" key, raise error
                if (ms_uris != null) {
                    throw new JSONException("metadata_statements and metadata_statement_uris cannot " +
                        "be present at the same time");
                }
                return msl;
            }

            // if there is not a "metadata_statements" nor "metadata_statement_uris" claim, return
            // an empty JSONArray
            if (ms_uris == null)
                return new JSONArray();

            // else, if there is a "metadata_statement_uris", iterate over all the URIs,
            // download them, and build a JSONArray with them
            JSONArray result = new JSONArray();
            for(Iterator<String> iter = ms_uris.keys(); iter.hasNext();) {
                String key = iter.next();
                HttpURLConnection conn = mConnectionBuilder.openConnection(JsonUtil.getUri(ms_uris, key));
                conn.setRequestMethod("GET");
                conn.setDoInput(true);
                conn.connect();
                InputStream is = conn.getInputStream();
                result.put(Utils.readInputStream(is));
            }
            return result;
        }

        /**
         * Verifies a compounded MS, gathering inner signing keys and using them to verify outer
         *      signatures.
         * @param ms_jwt JWT representing a signed metadata statement
         * @return A JSONObject (dict) with a entry per federation operator with the corresponding
         *      flattened and verified MS
         * @throws IOException
         */
        private JSONObject verify_ms(String ms_jwt) {
            try {
                // Parse the signed JWT
                SignedJWT signedJWT = SignedJWT.parse(ms_jwt);

                // Create an empty JWKS to store gathered keys from the inner MS
                JWKSet keys = new JWKSet();

                // convert nimbus JSON object to org.json.JSONObject for simpler processing
                JSONObject payload = new JSONObject(signedJWT.getPayload().toString());

                Log.d("FED", "Inspecting MS signed by: " + payload.getString("iss")
                    + " with KID:" + signedJWT.getHeader().getKeyID());

                // Get inner metadata statements
                JSONArray statements = get_metadata_statements(payload);

                // Create an empty list of flattened MS
                JSONObject flat_msl = new JSONObject();

                // if there are inner MS, iterate over them
                if (statements.length() > 0) {
                    for (int i = 0; i < statements.length(); i++) {
                        // verify each inner MS, obtaining their flattened version (per fedop ID)
                        JSONObject flat_sub_ms = verify_ms(statements.getString(i));

                        // for each flattened MS per fedop ID, add "signing_keys" to keys, and the
                        // MS to the result list
                        for(Iterator<String> iter = flat_sub_ms.keys(); iter.hasNext();) {
                            String fedop = iter.next();
                            JSONObject sub_ms = flat_sub_ms.getJSONObject(fedop);
                            JWKSet sub_signing_keys = JWKSet.parse(sub_ms.getJSONObject("signing_keys").toString());
                            keys.getKeys().addAll(sub_signing_keys.getKeys());
                            flat_msl.put(fedop, flatten(payload, sub_ms));
                        }
                    }
                }

                // if there are no inner metadata statements, this is MS0 and authorized keys must
                // be used for validating the signature. Flattened list consists just on this
                // payload and "iss" represents the federation operator ID
                else {
                    keys = JWKSet.parse(this.mAuthorizedKeys.toString());
                    flat_msl.put(payload.getString("iss"), payload);
                }

                // verify the signature of the signed JWT using any of the keys collected from the
                // inner MS
                verify_signature(signedJWT, keys);
                Log.d("FED", "Successful validation of signature of " + payload.getString("iss")
                    + " with KID:" + signedJWT.getHeader().getKeyID());
                return flat_msl;
            }
            // in case of any error, we omit the processing of this JWT, but let the recursive process continue
            catch (JOSEException | JSONException | ParseException | IOException | BadJOSEException e) {
                Log.d("FED", "Error validating MS. Ignoring. " + e.toString());
                return new JSONObject();
            }
        }

        /**
         * Given a discovery document, try to get a federated/signed version of it
         * @param discovery_doc Discovery document as retrieved from .well-known/openid-configuration
         * @return A discovery document which has been validated using a supported federation
         */
        private JSONObject getFederatedConfiguration(JSONObject discovery_doc) {
            try {
                // Get the inner metadata statements
                JSONArray metadata_statements = get_metadata_statements(discovery_doc);

                // if there are, create a dict with the MS corresponding to each FedOP ID
                if (metadata_statements.length() > 0) {
                    JSONObject flat_msl = new JSONObject();
                    for (int i=0; i<metadata_statements.length(); i++) {
                        String statement = metadata_statements.getString(i);
                        JSONObject _msl = verify_ms(statement);
                        for(Iterator<String> iter = _msl.keys(); iter.hasNext();) {
                            String key = iter.next();
                            flat_msl.put(key, _msl.get(key));
                        }
                    }
                    Log.d("FED", "We've got a total of " + flat_msl.length()
                        + " signed and flattened metadata statements");
                    for(Iterator<String> iter = flat_msl.keys(); iter.hasNext();) {
                        String key = iter.next();
                        JSONObject ms = flat_msl.getJSONObject(key);
                        Log.d("FED", "Statement for federation id " + key);
                        System.out.println(ms.toString(2));
                    }
                    if (flat_msl.length() == 0)
                        return new JSONObject();
                    else
                        return flat_msl;
                }
            } catch (IOException | JSONException e) {
                Log.d("FED", "There was a problem validating the federated metadata: " + e.toString());
            }
            return new JSONObject();
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

                JSONObject mss = getFederatedConfiguration(json);
                // get the first one and return
                for(Iterator<String> iter = mss.keys(); iter.hasNext();) {
                    String key = iter.next();
                    json = mss.getJSONObject(key);
                }

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
