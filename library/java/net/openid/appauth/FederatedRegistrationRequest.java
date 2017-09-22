/*
 * Copyright 2016 The AppAuth for Android Authors. All Rights Reserved.
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

import static net.openid.appauth.AdditionalParamsProcessor.builtInParams;
import static net.openid.appauth.AdditionalParamsProcessor.checkAdditionalParams;
import static net.openid.appauth.Preconditions.checkCollectionNotEmpty;
import static net.openid.appauth.Preconditions.checkNotEmpty;
import static net.openid.appauth.Preconditions.checkNotNull;

import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class FederatedRegistrationRequest extends RegistrationRequest {
    private static final Set<String> BUILT_IN_PARAMS = builtInParams(
        PARAM_REDIRECT_URIS,
        PARAM_RESPONSE_TYPES,
        PARAM_GRANT_TYPES,
        PARAM_APPLICATION_TYPE,
        PARAM_SUBJECT_TYPE,
        PARAM_TOKEN_ENDPOINT_AUTHENTICATION_METHOD
    );

    /**
     * Creates instances of {@link RegistrationRequest}.
     */
    public static final class Builder {
        @NonNull
        private AuthorizationServiceConfiguration mConfiguration;
        @NonNull
        private List<Uri> mRedirectUris = new ArrayList<>();

        @Nullable
        private List<String> mResponseTypes;

        @Nullable
        private List<String> mGrantTypes;

        @Nullable
        private String mSubjectType;

        @Nullable
        private String mTokenEndpointAuthenticationMethod;

        @NonNull
        private Map<String, String> mAdditionalParameters = Collections.emptyMap();


        /**
         * Creates a registration request builder with the specified mandatory properties.
         */
        public Builder(
            @NonNull AuthorizationServiceConfiguration configuration,
            @NonNull List<Uri> redirectUri) {
            setConfiguration(configuration);
            setRedirectUriValues(redirectUri);
        }

        /**
         * Specifies the authorization service configuration for the request, which must not
         * be null or empty.
         */
        @NonNull
        public Builder setConfiguration(@NonNull AuthorizationServiceConfiguration configuration) {
            mConfiguration = checkNotNull(configuration);
            return this;
        }

        /**
         * Specifies the redirect URI's.
         *
         * @see <a href="https://tools.ietf.org/html/rfc6749#section-3.1.2"> "The OAuth 2.0
         * Authorization Framework" (RFC 6749), Section 3.1.2</a>
         */
        @NonNull
        public Builder setRedirectUriValues(@NonNull Uri... redirectUriValues) {
            return setRedirectUriValues(Arrays.asList(redirectUriValues));
        }

        /**
         * Specifies the redirect URI's.
         *
         * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 3.1.2
         * <https://tools.ietf.org/html/rfc6749#section-3.1.2>"
         */
        @NonNull
        public Builder setRedirectUriValues(@NonNull List<Uri> redirectUriValues) {
            checkCollectionNotEmpty(redirectUriValues, "redirectUriValues cannot be null");
            mRedirectUris = redirectUriValues;
            return this;
        }

        /**
         * Specifies the response types.
         *
         * @see "OpenID Connect Core 1.0, Section 3
         * <https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3>"
         */
        @NonNull
        public Builder setResponseTypeValues(@Nullable String... responseTypeValues) {
            return setResponseTypeValues(Arrays.asList(responseTypeValues));
        }

        /**
         * Specifies the response types.
         *
         * @see "OpenID Connect Core 1.0, Section X
         * <https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.X>"
         */
        @NonNull
        public Builder setResponseTypeValues(@Nullable List<String> responseTypeValues) {
            mResponseTypes = responseTypeValues;
            return this;
        }

        /**
         * Specifies the grant types.
         *
         * @see "OpenID Connect Dynamic Client Registration 1.0, Section 2
         * <https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.2>"
         */
        @NonNull
        public Builder setGrantTypeValues(@Nullable String... grantTypeValues) {
            return setGrantTypeValues(Arrays.asList(grantTypeValues));
        }

        /**
         * Specifies the grant types.
         *
         * @see "OpenID Connect Dynamic Client Registration 1.0, Section 2
         * <https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.2>"
         */
        @NonNull
        public Builder setGrantTypeValues(@Nullable List<String> grantTypeValues) {
            mGrantTypes = grantTypeValues;
            return this;
        }

        /**
         * Specifies the subject types.
         *
         * @see "OpenID Connect Core 1.0, Section 8
         * <https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.8>"
         */
        @NonNull
        public Builder setSubjectType(@Nullable String subjectType) {
            mSubjectType = subjectType;
            return this;
        }

        /**
         * Specifies the client authentication method to use at the token endpoint.
         *
         * @see "OpenID Connect Core 1.0, Section 9
         * <https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.9>"
         */
        @NonNull
        public Builder setTokenEndpointAuthenticationMethod(
            @Nullable String tokenEndpointAuthenticationMethod) {
            this.mTokenEndpointAuthenticationMethod = tokenEndpointAuthenticationMethod;
            return this;
        }

        /**
         * Specifies additional parameters. Replaces any previously provided set of parameters.
         * Parameter keys and values cannot be null or empty.
         */
        @NonNull
        public Builder setAdditionalParameters(@Nullable Map<String, String> additionalParameters) {
            mAdditionalParameters = checkAdditionalParams(additionalParameters, BUILT_IN_PARAMS);
            return this;
        }

        /**
         * Constructs the registration request. At a minimum, the redirect URI must have been
         * set before calling this method.
         */
        @NonNull
        public FederatedRegistrationRequest build() {
            return new FederatedRegistrationRequest(
                mConfiguration,
                Collections.unmodifiableList(mRedirectUris),
                mResponseTypes == null
                    ? mResponseTypes : Collections.unmodifiableList(mResponseTypes),
                mGrantTypes == null ? mGrantTypes : Collections.unmodifiableList(mGrantTypes),
                mSubjectType,
                mTokenEndpointAuthenticationMethod,
                Collections.unmodifiableMap(mAdditionalParameters));
        }
    }

    protected FederatedRegistrationRequest(
        @NonNull AuthorizationServiceConfiguration configuration,
        @NonNull List<Uri> redirectUris,
        @Nullable List<String> responseTypes,
        @Nullable List<String> grantTypes,
        @Nullable String subjectType,
        @Nullable String tokenEndpointAuthenticationMethod,
        @NonNull Map<String, String> additionalParameters) {
        super(configuration, redirectUris, responseTypes, grantTypes, subjectType, tokenEndpointAuthenticationMethod, additionalParameters);
    }

    /**
     * Reads a registration request from a JSON string representation produced by
     * {@link #jsonSerialize()}.
     * @throws JSONException if the provided JSON does not match the expected structure.
     */
    public static RegistrationRequest jsonDeserialize(@NonNull JSONObject json)
        throws JSONException {
        checkNotNull(json, "json must not be null");
        List<Uri> redirectUris = JsonUtil.getUriList(json, PARAM_REDIRECT_URIS);

        Builder builder = new FederatedRegistrationRequest.Builder(
            AuthorizationServiceConfiguration.fromJson(json.getJSONObject(KEY_CONFIGURATION)),
            redirectUris)
            .setSubjectType(JsonUtil.getStringIfDefined(json, PARAM_SUBJECT_TYPE))
            .setResponseTypeValues(JsonUtil.getStringListIfDefined(json, PARAM_RESPONSE_TYPES))
            .setGrantTypeValues(JsonUtil.getStringListIfDefined(json, PARAM_GRANT_TYPES))
            .setAdditionalParameters(JsonUtil.getStringMap(json, KEY_ADDITIONAL_PARAMETERS));

        return builder.build();
    }

    protected JSONObject jsonSerializeParams() {
        JSONObject json = new JSONObject();
        JsonUtil.put(json, PARAM_REDIRECT_URIS, JsonUtil.toJsonArray(redirectUris));
        JsonUtil.put(json, PARAM_APPLICATION_TYPE, applicationType);

        if (responseTypes != null) {
            JsonUtil.put(json, PARAM_RESPONSE_TYPES, JsonUtil.toJsonArray(responseTypes));
        }
        if (grantTypes != null) {
            JsonUtil.put(json, PARAM_GRANT_TYPES, JsonUtil.toJsonArray(grantTypes));
        }
        JsonUtil.putIfNotNull(json, PARAM_SUBJECT_TYPE, subjectType);
        JsonUtil.putIfNotNull(json, PARAM_TOKEN_ENDPOINT_AUTHENTICATION_METHOD,
            tokenEndpointAuthenticationMethod);
        try {
            json.put("metadata_statements", new JSONObject("{\"https://swamid.sunet.se\": " +
                "\"eyJraWQiOiJQSjYzMmMwWF9JVlNtSFZ2dkRRX0pXQzVxbWtCb20tTXlDMWowMlkyU1hFIiwiYWxnIjoiUlMyNTYifQ.eyJpYXQiOiAxNTA2MDY0NjAzLCAianRpIjogIjQ2NGUzMTg0N2NkMDQ3MDE5YjU3NmU2OGQ2MDRhZWFiIiwgImlzcyI6ICJodHRwczovL3N3YW1pZC5zdW5ldC5zZSIsICJraWQiOiAiUEo2MzJjMFhfSVZTbUhWdnZEUV9KV0M1cW1rQm9tLU15QzFqMDJZMlNYRSIsICJzaWduaW5nX2tleXMiOiB7ImtleXMiOiBbeyJ1c2UiOiAic2lnIiwgImUiOiAiQVFBQiIsICJuIjogInFGYS0xaU41bEM2Q2RPUXN0cDVqM2JVYW5ZeXNkUDY3a3duZk5jNk9SWmFRRnMwNV9nZDBGalhDYkVwTnNOXy1jWlhOM2ZlYzlBMGRwOWFMajd5VTNHR0wyR0dJdDM1RDhRWmkzUld5ZFdpNHZ2U1ZFdlNNUHBZWUNZX3djSDdHeEhVc0wwa1RCOThseGdCeWs2SFR5WDhDNHhyVngyZHdJb2MzaFVBek5kNmF0SGwwY0hPaTVpOTRIbUxHQmNrV0E2T3lqMWhCenY5dFFyRUlYVFpKOEtZcUhUb1ZqX2FRZlJNRlVMQlc1eGhlRHFvNF9MNFprakdVVlVOSE5BNHBQZHpwTl82b3FvSS01T0pzTnE4ZXplQjVoZE4yc0k0MnBKVFNxY1JhVVVOR3R5cUdTQVdaMWxGSzJhVXBUWTFmVWdzaFItZUVyRlVxaExtQmtPOW1TdyIsICJraWQiOiAia3VqMWtCTjVKU2NuRkZjQ2dZaGZuVlZZdm5uNTNFQXNXeWhRY0ZVU1NfOCIsICJrdHkiOiAiUlNBIn0sIHsieCI6ICJIelVMNVFiakxScGpnNnM3TzVkUUNMSm9kd182Mnh2ZkNoLUZXbVFvNU5RIiwgInkiOiAicVFGNlY4MVlMUWJUdXpQYzg4TmE2bEROS2RZdENiVXh4cWdIbkFnY2k3QSIsICJraWQiOiAidnZOSVR1dDJCZV94QkZzTzZMQkpzWnhHdDNkTzdtdXNIOTdmOENCX1ExOCIsICJrdHkiOiAiRUMiLCAidXNlIjogInNpZyIsICJjcnYiOiAiUC0yNTYifV19LCAiZXhwIjogMTUwNjA2NDYwMywgImF1ZCI6IFsiaHR0cHM6Ly9zdW5ldC5zZSJdLCAiZmVkZXJhdGlvbl91c2FnZSI6ICJyZWdpc3RyYXRpb24ifQ.DClWMfDxJYLdsH5yOSJjODzYz6Q9ITwWU6sblADS8t7xPcqIuu1SpGt_FKDSJJeVjtJvIKOB_yg-Sl2QAlmCbj5etO8WungIZsxenStkG_QKFUF0pH1pt6BD-T4yqtYY-w0rc9u2CW9z1GPcT3v0eX42uvxjLbYPL2pQPDSJsxDIfS_S1TkfrCpamXlJC_k8mGeOJJczLKjGIwBmekyOODsN5Pykix5RlmpumWZ9-zvGPdQ7Yz84Z4d24DMQ_PMr5ZXQyVTwBr3nyD_moB39ioTuggyX-5qiJTUlyFXyGPRylPL_fgCWlftGEvBuGAcbhP0aRbyp8BproM-wN6hmGw\"}"));
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return json;
    }
}


