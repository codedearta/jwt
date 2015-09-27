package org.dearta.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.LocalDate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Created by sepp on 27.09.15.
 */
public class JwtToken {
    public static final String AUTHENTICATION_SCHEME = "Baerer ";
    public final Map<String,String>  headers;
    public final Map<String,String> claims;
    public byte[] signature;

    public JwtToken(Map<String, String> claims, String secret) throws Exception {
        this(new HashMap<String, String>() {{ put("alg", "HS256"); put("typ", "JWT"); }} ,claims,secret);
    }

    private JwtToken(Map<String,String> headers, Map<String, String> claims, String secret) throws Exception {
        this.headers = headers;
        this.claims = claims;
        this.signature = encodeHmac(secret,payloadAsBase64());
    }

    private JwtToken(Map<String,String> headers, Map<String, String> claims) throws Exception {
        this.headers = headers;
        this.claims = claims;
    }

    public String toBase64() throws Exception {
        String signatureBase64 = new String(Base64.getEncoder().encode(signature));
        String encodedJWT = payloadAsBase64() + "." + signatureBase64;
        return encodedJWT;
    }

    private String payloadAsBase64() throws JsonProcessingException {
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        String headersJson = ow.writeValueAsString(this.headers);
        String headersBase64 = new String(Base64.getEncoder().encode(headersJson.getBytes()));
        String claimsJson = ow.writeValueAsString(this.claims);
        String claimsBase64 = new String(Base64.getEncoder().encode(claimsJson.getBytes()));
        return headersBase64 + "." + claimsBase64;
    }

    private byte[] encodeHmac(String secret, String data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        String slatedSecret = LocalDate.now().toString() + secret;
        SecretKeySpec secret_key = new SecretKeySpec(slatedSecret.getBytes("UTF-8"), "HmacSHA256");
        sha256_HMAC.init(secret_key);

        return sha256_HMAC.doFinal(data.getBytes("UTF-8"));
    }

    public static JwtToken parseToken(String tokenString2) throws Exception {
        if(tokenString2.startsWith(AUTHENTICATION_SCHEME)) {
            String tokenWithNoSchema = tokenString2.replace(AUTHENTICATION_SCHEME, "");
            String[] parts = tokenWithNoSchema.split(Pattern.quote("."));
            String headersJson = new String(Base64.getDecoder().decode(parts[0].getBytes()));
            String claimsJson = new String(Base64.getDecoder().decode(parts[1].getBytes()));

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, String> jwtHeader = objectMapper.readValue(headersJson, Map.class);
            Map<String, String> claims = objectMapper.readValue(claimsJson, Map.class);
            JwtToken jwtToken = new JwtToken(jwtHeader, claims);
            jwtToken.signature = Base64.getDecoder().decode(parts[2]);
            return jwtToken;
        }

        throw new Exception("invalid token");
    }

    public static boolean verifyToken(String tokenString, String secret) throws Exception {
        JwtToken pasedJwtToken = parseToken(tokenString);
        JwtToken serverToken = new JwtToken(pasedJwtToken.headers, pasedJwtToken.claims, secret);
        String serverSignature = new String(serverToken.signature);
        String parsedSignature = new String(pasedJwtToken.signature);
        return serverSignature.equals(parsedSignature);
    }
}
