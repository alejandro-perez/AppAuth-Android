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
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

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

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

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

    public String parseBody(String jwt) {
        int i = jwt.indexOf('.');
        int j = jwt.lastIndexOf('.');
        String body = jwt.substring(i, j);
        byte[] json = Base64.decode(body, Base64.DEFAULT);
        return new String(json);
    }

    public String parseHeader(String jwt) {
        int i = jwt.indexOf('.');
        String header = jwt.substring(0, i);
        byte[] json = Base64.decode(header, Base64.DEFAULT);
        return new String(json);
    }

    public static PublicKey getPublicKeyFromString(String modulus_str, String exponent_str) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger modulus = new BigInteger(1, Base64.decode(modulus_str, Base64.URL_SAFE));
        BigInteger exponent = new BigInteger(1, Base64.decode(exponent_str, Base64.URL_SAFE));
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    private PublicKey getKeyFromKid(String kid, JSONArray keys) throws JSONException, InvalidKeySpecException, NoSuchAlgorithmException {
        for (int i = 0; i < keys.length(); i++) {
            JSONObject jwk = keys.getJSONObject(i);
            if (jwk.getString("kid").equals(kid)) {
                return getPublicKeyFromString(jwk.getString("n"), jwk.getString("e"));
            }
        }
        return null;
    }

    private Boolean verify_ms(String ms_jwt, JSONArray keys) throws JSONException, InvalidKeySpecException, NoSuchAlgorithmException {
        String json_text = this.parseBody(ms_jwt);
        JSONObject ms = new JSONObject(json_text);
        Log.d("FED", "Inspecting MS signed by: " + ms.getString("iss"));
        if (ms.has("metadata_statements")) {
            JSONArray statements = ms.getJSONArray("metadata_statements");
            for (int i = 0; i < statements.length(); i++) {
                verify_ms(statements.getString(i), keys);
            }
        }
        // This is where validation takes place
        Log.d("FED", "Validating signature of " + ms.getString("iss"));
        JSONObject header = new JSONObject(this.parseHeader(ms_jwt));
        PublicKey signing_key = this.getKeyFromKid(header.getString("kid"), keys);
        try {
            JwtParser parser = Jwts.parser()
                .setAllowedClockSkewSeconds(300000000) // THIS SHOULD NOT BE DONE THIS WAY
                .setSigningKey(signing_key);
            parser.parseClaimsJws(ms_jwt);
            Log.d("FED", ms.getString("iss") + " validated");

            // add keys to the list
            JSONArray signing_keys = ms.getJSONArray("signing_keys");
            for (int i = 0; i < signing_keys.length(); i++) {
                JSONObject key = signing_keys.getJSONObject(i);
                Log.d("FED", "Adding key " + key.getString("kid"));
                keys.put(signing_keys.getJSONObject(i));
            }
            Log.d("FED", "Keys: " + keys.length() + " " + keys.toString(2));
        } catch(Exception exception) {
            Log.d("FED", ms.getString("iss") + " failed:" + exception);
            return false;
        }
        return true;
    }

    @MainThread
    private void handleConfigurationRetrievalResult(
            AuthorizationServiceConfiguration config, AuthorizationException ex) {
        if (config == null) {
            displayError("Failed to retrieve discovery document: " + ex.getMessage(), true);
            return;
        }

        // if there are metadata statements, try to validate them first
        List<String> metadata_statements = config.discoveryDoc.getMetadataStatements();
        if (metadata_statements != null){
            JSONArray keys = mConfiguration.getAuthorizedKeys();
            for (String statement: metadata_statements) {
                try {
                    if (this.verify_ms(statement, keys))
                        Log.d("FED", "MS was successfully validated and we have collected the following keys: " + keys.toString(2));
                    else
                        Log.d("FED", "MS could not be validated having the following keys: " + keys.toString(2));
                } catch (Exception exception){
                    Log.d("FED", "Error decoding JWT: " + exception);
                }

            }
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
