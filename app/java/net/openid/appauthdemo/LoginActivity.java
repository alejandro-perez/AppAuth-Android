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

package net.openid.appauthdemo;

import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.AnyThread;
import android.support.annotation.ColorRes;
import android.support.annotation.MainThread;
import android.support.annotation.NonNull;
import android.support.annotation.WorkerThread;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;

import net.minidev.json.JSONUtil;
import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.ClientSecretBasic;
import net.openid.appauth.RegistrationRequest;
import net.openid.appauth.RegistrationResponse;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.browser.AnyBrowserMatcher;
import net.openid.appauth.browser.BrowserMatcher;
import net.openid.appauth.browser.ExactBrowserMatcher;
import net.openid.appauthdemo.BrowserSelectionAdapter.BrowserInfo;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.lang.reflect.Array;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Demonstrates the usage of the AppAuth to authorize a user with an OAuth2 / OpenID Connect
 * provider. Based on the configuration provided in `res/raw/auth_config.json`, the code
 * contained here will:
 *
 * - Retrieve an OpenID Connect discovery document for the provider, or use a local static
 *   configuration.
 * - Utilize dynamic client registration, if no static client id is specified.
 * - Initiate the authorization request using the built-in heuristics or a user-selected browser.
 *
 * _NOTE_: From a clean checkout of this project, the authorization service is not configured.
 * Edit `res/values/auth_config.xml` to provide the required configuration properties. See the
 * README.md in the app/ directory for configuration instructions, and the adjacent IDP-specific
 * instructions.
 */
public final class LoginActivity extends AppCompatActivity {

    private static final String TAG = "LoginActivity";
    private static final String EXTRA_FAILED = "failed";

    private AuthorizationService mAuthService;
    private AuthStateManager mAuthStateManager;
    private Configuration mConfiguration;

    private final AtomicReference<String> mClientId = new AtomicReference<>();
    private ExecutorService mExecutor;

    @NonNull
    private BrowserMatcher mBrowserMatcher = AnyBrowserMatcher.INSTANCE;

    private static void disableSSLCertificateChecking() {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                // Not implemented
            }

            @Override
            public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                // Not implemented
            }
        } };

        try {
            SSLContext sc = SSLContext.getInstance("TLS");

            sc.init(null, trustAllCerts, new java.security.SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mExecutor = Executors.newSingleThreadExecutor();
        mAuthStateManager = AuthStateManager.getInstance(this);
        mConfiguration = Configuration.getInstance(this);

        if (mAuthStateManager.getCurrent().isAuthorized()
                && !mConfiguration.hasConfigurationChanged()) {
            startActivity(new Intent(this, TokenActivity.class));
            finish();
            return;
        }

        setContentView(R.layout.activity_login);

        findViewById(R.id.retry).setOnClickListener((View view) ->
                mExecutor.submit(this::initializeAppAuth));
        findViewById(R.id.start_auth).setOnClickListener((View view) -> startAuth());

        if (!mConfiguration.isValid()) {
            displayError(mConfiguration.getConfigurationError(), false);
            return;
        }

        configureBrowserSelector();
        this.disableSSLCertificateChecking();

        if (mConfiguration.hasConfigurationChanged()) {
            // discard any existing authorization state due to the change of configuration
            Log.i(TAG, "Configuration change detected, discarding old state");
            mAuthStateManager.replace(new AuthState());
            mConfiguration.acceptConfiguration();
        }

        if (getIntent().getBooleanExtra(EXTRA_FAILED, false)) {
            Snackbar.make(findViewById(R.id.coordinator),
                    "Authorization canceled",
                    Snackbar.LENGTH_SHORT)
                    .show();
        }

        displayLoading("Initializing");
        mExecutor.submit(this::initializeAppAuth);
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (mExecutor.isShutdown()) {
            mExecutor = Executors.newSingleThreadExecutor();
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        mExecutor.shutdownNow();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        if (mAuthService != null) {
            mAuthService.dispose();
        }
    }

    @MainThread
    void startAuth() {
        final String loginHint = ((EditText) findViewById(R.id.login_hint_value))
                .getText()
                .toString()
                .trim();

        displayLoading("Making authorization request");

        // WrongThread inference is incorrect for lambdas
        // noinspection WrongThread
        mExecutor.submit(() -> doAuth(loginHint));
    }

    /**
     * Initializes the authorization service configuration if necessary, either from the local
     * static values or by retrieving an OpenID discovery document.
     */
    @WorkerThread
    private void initializeAppAuth() {
        recreateAuthorizationService();

        if (mAuthStateManager.getCurrent().getAuthorizationServiceConfiguration() != null) {
            // configuration is already created, skip to client initialization
            initializeClient();
            return;
        }

        // if we are not using discovery, build the authorization service configuration directly
        // from the static configuration values.
        if (mConfiguration.getDiscoveryUri() == null) {
            AuthorizationServiceConfiguration config = new AuthorizationServiceConfiguration(
                    mConfiguration.getAuthEndpointUri(),
                    mConfiguration.getTokenEndpointUri(),
                    mConfiguration.getRegistrationEndpointUri());

            mAuthStateManager.replace(new AuthState(config));
            initializeClient();
            return;
        }

        // WrongThread inference is incorrect for lambdas
        // noinspection WrongThread
        runOnUiThread(() -> displayLoading("Retrieving discovery document"));
        AuthorizationServiceConfiguration.fetchFromUrl(
                mConfiguration.getDiscoveryUri(),
                this::handleConfigurationRetrievalResult,
                mConfiguration.getConnectionBuilder());
    }

    private boolean is_lesser(Object obj1, Object obj2) throws JSONException {
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
            boolean found = false;
            for (int i=0; i<list1.length(); i++){
                for (int j=0; j<list2.length(); j++){
                    if (is_lesser(list1.get(i), list2.get(j))) {
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
            Iterator<String> it = jobj1.keys();
            while (it.hasNext()){
                String key = it.next();
                if (!is_lesser(jobj1.get(key), jobj2.opt(key)))
                    return false;
            }
            return true;
        }
        else
            throw new JSONException("Unexpeccted JSON class: " + obj1.getClass().toString());
    }

    private JSONObject flatten(JSONObject upper, JSONObject lower) throws JSONException {
        String[] use_lower = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"};
        String[] use_upper = {"signing_keys", "signing_keys_uri", "metadata_statement_uris", "kid",
                              "metadata_statements", "usage"};
        JSONObject flattened = new JSONObject(lower.toString());
        Iterator<String> it = upper.keys();
        while (it.hasNext()){
            String claim_name = it.next();
            if (Arrays.asList(use_lower).contains(claim_name))
                continue;
            if (lower.opt(claim_name) == null
                    || Arrays.asList(use_upper).contains(claim_name)
                    || this.is_lesser(upper.get(claim_name), lower.get(claim_name)))
                flattened.put(claim_name, upper.get(claim_name));
        }
        return flattened;
    }

    private void verify_signature(SignedJWT signedJWT, JWKSet keys) throws BadJOSEException, JOSEException {
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(
            signedJWT.getHeader().getAlgorithm(),
            new ImmutableJWKSet(keys));
        DefaultJWTClaimsVerifier cverifier = new DefaultJWTClaimsVerifier();
        cverifier.setMaxClockSkew(500000000);
        jwtProcessor.setJWTClaimsSetVerifier(cverifier);
        jwtProcessor.setJWSKeySelector(keySelector);
        jwtProcessor.process(signedJWT, null);
    }

    private JSONArray verify_ms(String ms_jwt, JWKSet root_keys) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(ms_jwt);
            JWKSet keys = new JWKSet();
            JSONArray flat_msl = new JSONArray();
            // convert nimbus JSON object to org.json.JSONObject for simpler processing
            JSONObject payload = new JSONObject(signedJWT.getPayload().toString());
            Log.d("FED", "Inspecting MS signed by: " + payload.getString("iss") + " with KID:"
                         + signedJWT.getHeader().getKeyID());
            if (payload.has("metadata_statements")) {
                JSONArray statements = payload.getJSONArray("metadata_statements");
                for (int i = 0; i < statements.length(); i++) {
                    JSONArray flat_sub_ms = verify_ms(statements.getString(i), root_keys);
                    for (int j = 0; j < flat_sub_ms.length(); j++){
                        JSONObject sub_ms = flat_sub_ms.getJSONObject(j);
                        JWKSet sub_signing_keys= JWKSet.parse(
                            sub_ms.getJSONObject("signing_keys").toString());
                        keys.getKeys().addAll(sub_signing_keys.getKeys());
                        flat_msl.put(this.flatten(payload, sub_ms));
                    }
                }
            }
            else {
                keys = root_keys;
                flat_msl.put(payload);
            }
            this.verify_signature(signedJWT, keys);
            Log.d("FED", "Successful validation of signature of " + payload.getString("iss")
                         + " with KID:" + signedJWT.getHeader().getKeyID());
            return flat_msl;
        } catch (JOSEException | JSONException | ParseException | BadJOSEException e) {
            Log.d("FED", "Error validating MS." + e.toString());
            e.printStackTrace();
            return new JSONArray();
        }
    }

    @MainThread
    private void handleConfigurationRetrievalResult(
            AuthorizationServiceConfiguration config, AuthorizationException ex) {
        if (config == null) {
            displayError("Failed to retrieve discovery document: " + ex.getMessage(), true);
            return;
        }

        // if there are metadata statements, get a flat version of them
        try {
            List<String> metadata_statements = config.discoveryDoc.getMetadataStatements();
            if (metadata_statements != null) {
                Log.d("FED", "OP provides " + metadata_statements.size() + " statements");
                JWKSet root_keys = JWKSet.parse(mConfiguration.getAuthorizedKeys().toString());
                JSONArray flat_msl = new JSONArray();
                for (String statement : metadata_statements) {
                    JSONArray _msl = this.verify_ms(statement, root_keys);
                    for (int i = 0; i < _msl.length(); i++)
                        flat_msl.put(_msl.get(i));
                }
                Log.d("FED", "We've got a total of " + flat_msl.length() + " signed and flattened metadata statements");
                for (int i = 0; i < flat_msl.length(); i++) {
                    JSONObject ms = flat_msl.getJSONObject(i);
                    Log.d("FED", "Statement for federation id " + ms.getString("iss"));
                    System.out.println(ms.toString(2));
                }
            }
        } catch (JSONException | ParseException e) {
            Log.d("FED", "There was a problem validating the metadata. Check strack trace for more details");
            e.printStackTrace();
        }

        mAuthStateManager.replace(new AuthState(config));
        mExecutor.submit(this::initializeClient);
    }

        /**
     * Initiates a dynamic registration request if a client ID is not provided by the static
     * configuration.
     */
    @WorkerThread
    private void initializeClient() {

        if (mConfiguration.getClientId() != null) {
            // use a statically configured client ID
            mClientId.set(mConfiguration.getClientId());
            runOnUiThread(this::displayAuthOptions);
            return;
        }

        RegistrationResponse lastResponse =
                mAuthStateManager.getCurrent().getLastRegistrationResponse();
        if (lastResponse != null) {
            // already dynamically registered a client ID
            mClientId.set(lastResponse.clientId);
            runOnUiThread(this::displayAuthOptions);
            return;
        }

        // WrongThread inference is incorrect for lambdas
        // noinspection WrongThread
        runOnUiThread(() -> displayLoading("Dynamically registering client"));

        RegistrationRequest registrationRequest = new RegistrationRequest.Builder(
                mAuthStateManager.getCurrent().getAuthorizationServiceConfiguration(),
                Collections.singletonList(mConfiguration.getRedirectUri()))
                .setTokenEndpointAuthenticationMethod(ClientSecretBasic.NAME)
                .build();

        mAuthService.performRegistrationRequest(
                registrationRequest,
                this::handleRegistrationResponse);
    }

    @MainThread
    private void handleRegistrationResponse(
            RegistrationResponse response,
            AuthorizationException ex) {
        mAuthStateManager.updateAfterRegistration(response, ex);
        if (response == null) {
            displayErrorLater("Failed to register client: " + ex.getMessage(), true);
            return;
        }

        mClientId.set(response.clientId);
        displayAuthOptions();
    }

    /**
     * Enumerates the browsers installed on the device and populates a spinner, allowing the
     * demo user to easily test the authorization flow against different browser and custom
     * tab configurations.
     */
    @MainThread
    private void configureBrowserSelector() {
        Spinner spinner = (Spinner) findViewById(R.id.browser_selector);
        final BrowserSelectionAdapter adapter = new BrowserSelectionAdapter(this);
        spinner.setAdapter(adapter);
        spinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                BrowserInfo info = adapter.getItem(position);
                if (info == null) {
                    mBrowserMatcher = AnyBrowserMatcher.INSTANCE;
                    return;
                } else {
                    mBrowserMatcher = new ExactBrowserMatcher(info.mDescriptor);
                }

                recreateAuthorizationService();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                mBrowserMatcher = AnyBrowserMatcher.INSTANCE;
            }
        });
    }

    /**
     * Performs the authorization request, using the browser selected in the spinner,
     * and a user-provided `login_hint` if available.
     */
    @WorkerThread
    private void doAuth(@NonNull String loginHint) {
        AuthorizationRequest.Builder authRequestBuilder = new AuthorizationRequest.Builder(
                mAuthStateManager.getCurrent().getAuthorizationServiceConfiguration(),
                mClientId.get(),
                ResponseTypeValues.CODE,
                mConfiguration.getRedirectUri())
                .setScope(mConfiguration.getScope());

        if (!TextUtils.isEmpty(loginHint)) {
            authRequestBuilder.setLoginHint(loginHint);
        }

        Intent completionIntent = new Intent(this, TokenActivity.class);
        Intent cancelIntent = new Intent(this, LoginActivity.class);
        cancelIntent.putExtra(EXTRA_FAILED, true);
        cancelIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);

        mAuthService.performAuthorizationRequest(
                authRequestBuilder.build(),
                PendingIntent.getActivity(this, 0, completionIntent, 0),
                PendingIntent.getActivity(this, 0, cancelIntent, 0),
                mAuthService.createCustomTabsIntentBuilder()
                        .setToolbarColor(getColorCompat(R.color.colorPrimary))
                        .build());
    }

    private void recreateAuthorizationService() {
        if (mAuthService != null) {
            mAuthService.dispose();
        }
        mAuthService = createAuthorizationService();
    }

    private AuthorizationService createAuthorizationService() {
        AppAuthConfiguration.Builder builder = new AppAuthConfiguration.Builder();
        builder.setBrowserMatcher(mBrowserMatcher);
        builder.setConnectionBuilder(mConfiguration.getConnectionBuilder());

        return new AuthorizationService(this, builder.build());
    }

    @MainThread
    private void displayLoading(String loadingMessage) {
        findViewById(R.id.loading_container).setVisibility(View.VISIBLE);
        findViewById(R.id.auth_container).setVisibility(View.GONE);
        findViewById(R.id.error_container).setVisibility(View.GONE);

        ((TextView)findViewById(R.id.loading_description)).setText(loadingMessage);
    }

    @MainThread
    private void displayError(String error, boolean recoverable) {
        findViewById(R.id.error_container).setVisibility(View.VISIBLE);
        findViewById(R.id.loading_container).setVisibility(View.GONE);
        findViewById(R.id.auth_container).setVisibility(View.GONE);

        ((TextView)findViewById(R.id.error_description)).setText(error);
        findViewById(R.id.retry).setVisibility(recoverable ? View.VISIBLE : View.GONE);
    }

    // WrongThread inference is incorrect in this case
    @SuppressWarnings("WrongThread")
    @AnyThread
    private void displayErrorLater(final String error, final boolean recoverable) {
        runOnUiThread(() -> displayError(error, recoverable));
    }

    @MainThread
    private void displayAuthOptions() {
        findViewById(R.id.auth_container).setVisibility(View.VISIBLE);
        findViewById(R.id.loading_container).setVisibility(View.GONE);
        findViewById(R.id.error_container).setVisibility(View.GONE);

        AuthState state = mAuthStateManager.getCurrent();
        AuthorizationServiceConfiguration config = state.getAuthorizationServiceConfiguration();

        String authEndpointStr;
        if (config.discoveryDoc != null) {
            authEndpointStr = "Discovered auth endpoint: \n";
        } else {
            authEndpointStr = "Static auth endpoint: \n";
        }
        authEndpointStr += config.authorizationEndpoint;
        ((TextView)findViewById(R.id.auth_endpoint)).setText(authEndpointStr);

        String clientIdStr;
        if (state.getLastRegistrationResponse() != null) {
            clientIdStr = "Dynamic client ID: \n";
        } else {
            clientIdStr = "Static client ID: \n";
        }
        clientIdStr += mClientId;
        ((TextView)findViewById(R.id.client_id)).setText(clientIdStr);
    }

    @TargetApi(Build.VERSION_CODES.M)
    @SuppressWarnings("deprecation")
    private int getColorCompat(@ColorRes int color) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return getColor(color);
        } else {
            return getResources().getColor(color);
        }
    }
}
