package net.openid.appauthdemo;

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

import net.openid.appauth.AuthorizationServiceConfiguration;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * Created by alex on 2/05/17.
 */

public class Federation {
    private static boolean is_subset(Object obj1, Object obj2) throws JSONException {
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
            Iterator<String> it = jobj1.keys();
            while (it.hasNext()){
                String key = it.next();
                if (!jobj2.has(key) || !is_subset(jobj1.get(key), jobj2.get(key)))
                    return false;
            }
            return true;
        }
        else
            throw new JSONException("Unexpected JSON class: " + obj1.getClass().toString());
    }

    private static JSONObject flatten(JSONObject upper, JSONObject lower) throws JSONException {
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
                || is_subset(upper.get(claim_name), lower.get(claim_name))) {
                flattened.put(claim_name, upper.get(claim_name));
            }
            else {
                throw new JSONException("Policy breach with claim: " + claim_name
                    + ". Lower value=" + lower.get(claim_name)
                    + ". Upper value=" + upper.get(claim_name));
            }
        }
        return flattened;
    }

    private static void verify_signature(SignedJWT signedJWT, JWKSet keys) throws BadJOSEException, JOSEException {
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(signedJWT.getHeader().getAlgorithm(),
            new ImmutableJWKSet(keys));
        DefaultJWTClaimsVerifier cverifier = new DefaultJWTClaimsVerifier();
        cverifier.setMaxClockSkew(5000000);
        jwtProcessor.setJWTClaimsSetVerifier(cverifier);
        jwtProcessor.setJWSKeySelector(keySelector);
        jwtProcessor.process(signedJWT, null);
    }

    public static JSONArray verify_ms(String ms_jwt, JWKSet root_keys) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(ms_jwt);
            JWKSet keys = new JWKSet();
            JSONArray flat_msl = new JSONArray();
            // convert nimbus JSON object to org.json.JSONObject for simpler processing
            JSONObject payload = new JSONObject(signedJWT.getPayload().toString());
            Log.d("FED", "Inspecting MS signed by: " + payload.getString("iss")
                + " with KID:" + signedJWT.getHeader().getKeyID());
            if (payload.has("metadata_statements")) {
                JSONArray statements = payload.getJSONArray("metadata_statements");
                for (int i = 0; i < statements.length(); i++) {
                    JSONArray flat_sub_ms = verify_ms(statements.getString(i), root_keys);
                    for (int j = 0; j < flat_sub_ms.length(); j++){
                        JSONObject sub_ms = flat_sub_ms.getJSONObject(j);
                        JWKSet sub_signing_keys= JWKSet.parse(sub_ms.getJSONObject("signing_keys").toString());
                        keys.getKeys().addAll(sub_signing_keys.getKeys());
                        flat_msl.put(flatten(payload, sub_ms));
                    }
                }
            }
            else {
                keys = root_keys;
                flat_msl.put(payload);
            }
            verify_signature(signedJWT, keys);
            Log.d("FED", "Successful validation of signature of " + payload.getString("iss")
                + " with KID:" + signedJWT.getHeader().getKeyID());
            return flat_msl;
        } catch (JOSEException | JSONException | ParseException | BadJOSEException e) {
            Log.d("FED", "Error validating MS. Ignoring. " + e.toString());
            return new JSONArray();
        }
    }

    public static JSONObject getFederatedConfiguration(Configuration mConfiguration,
                                                       AuthorizationServiceConfiguration config){
        // if there are metadata statements, get a flat version of them
        try {
            JSONArray metadata_statements = config.discoveryDoc.docJson.getJSONArray("metadata_statements");
            if (metadata_statements != null) {
                Log.d("FED", "OP provides " + metadata_statements.length() + " statements");
                JWKSet root_keys = JWKSet.parse(mConfiguration.getAuthorizedKeys().toString());
                JSONArray flat_msl = new JSONArray();
                for (int i=0; i<metadata_statements.length(); i++) {
                    String statement = metadata_statements.getString(i);
                    JSONArray _msl = verify_ms(statement, root_keys);
                    for (int j = 0; j < _msl.length(); j++)
                        flat_msl.put(_msl.get(j));
                }
                Log.d("FED", "We've got a total of " + flat_msl.length()
                    + " signed and flattened metadata statements");
                for (int i = 0; i < flat_msl.length(); i++) {
                    JSONObject ms = flat_msl.getJSONObject(i);
                    Log.d("FED", "Statement for federation id " + ms.getString("iss"));
                    System.out.println(ms.toString(2));
                }
                if (flat_msl.length() == 0)
                    return null;
                else
                    return flat_msl.getJSONObject(0);
            }
        } catch (JSONException | ParseException e) {
            Log.d("FED", "There was a problem validating the federated metadata: " + e.toString());
        }
        return null;
    }
}
