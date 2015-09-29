package org.dearta.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Created by sepp on 27.09.15.
 */
public class JwtToken {

    public static final String JOSE_NAME_ALGORITHM = "alg ";
    public static final String JOSE_NAME_TYPE = "typ ";

    public static final String CLAIM_NAME_ID = "jti ";
    public static final String CLAIM_NAME_ISSUER = "iss ";
    public static final String CLAIM_NAME_EXPIRE = "exp ";
    public static final String CLAIM_NAME_CLIENT_IP = "cip ";
    public static final String CLAIM_NAME_USER = "usr";

    public static final String AUTHENTICATION_SCHEME = "Baerer";

    public final Map<String, String> headers = new HashMap<String, String>();
    public final Map<String, String> claims = new HashMap<String, String>();
    public byte[] signature;

    JwtToken(){

    }

    public JwtToken(String issuer){
        headers.put(JOSE_NAME_ALGORITHM, "HS256");
        headers.put(JOSE_NAME_TYPE, "JWT");
        withIssuerClaim(issuer);
    }

    public JwtToken withIssuerClaim(String issuer) {
        claims.put(CLAIM_NAME_ISSUER, issuer);
        return this;
    }

    public JwtToken withUserClaim(String username) {
        claims.put(CLAIM_NAME_USER, username);
        return this;
    }

    public JwtToken withClientIpClaim(String clientIp) {
        claims.put(CLAIM_NAME_CLIENT_IP, clientIp);
        return this;
    }

    public JwtToken withIdClaim() {
        claims.put(CLAIM_NAME_ID, UUID.randomUUID().toString());
        return this;
    }

    public JwtToken withExpireClaim(int minutes) {
        claims.put(CLAIM_NAME_EXPIRE, LocalDateTime.now().plusMinutes(minutes).format(DateTimeFormatter.ISO_DATE_TIME));
        return this;
    }

    public JwtToken withCustomClaim(String claimName, String claimValue) {
        claims.put(claimName, claimValue);
        return this;
    }

    public JwtToken withCustomHeader(String headerName, String headerValue) {
        headers.put(headerName, headerValue);
        return this;
    }

    public JwtToken sign(String key) throws Exception {
        this.signature = encodeHmac(key, payloadAsBase64());
        return this;
    }

    public String toBase64() throws Exception {
        return signature == null ? payloadAsBase64() : payloadAsBase64() + "." + new String(Base64.getEncoder().encode(signature));
    }

    public static JwtToken verifyTokenSignature(String tokenString, String issuer, String secret) throws Exception {
        JwtToken parsedJwtToken = parseTokenFrom(tokenString);

        JwtToken serverToken = new JwtToken(issuer);
        serverToken.headers.putAll(parsedJwtToken.headers);
        serverToken.claims.putAll(parsedJwtToken.claims);
        serverToken.withIssuerClaim(issuer);
        serverToken.sign(secret);

        String serverSignature = new String(serverToken.signature);
        String parsedSignature = new String(parsedJwtToken.signature);
        if(serverSignature.equals(parsedSignature)) {
            return parsedJwtToken;
        }

        throw new Exception("invalid token");
    }

    public JwtToken verifyExpiration() throws Exception {
        if (LocalDateTime.now().isAfter(LocalDateTime.parse(this.claims.get(JwtToken.CLAIM_NAME_EXPIRE), DateTimeFormatter.ISO_DATE_TIME))){
            throw new Exception("invalid Token");
        }

        return this;
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
        String saltedSecret = LocalDate.now().toString() + secret;
        SecretKeySpec secret_key = new SecretKeySpec(saltedSecret.getBytes("UTF-8"), "HmacSHA256");
        sha256_HMAC.init(secret_key);

        return sha256_HMAC.doFinal(data.getBytes("UTF-8"));
    }

    private static JwtToken parseTokenFrom(String tokenString) throws Exception {
        String tokenWithNoSchema = tokenString.replace(AUTHENTICATION_SCHEME, "").trim();
        String[] parts = tokenWithNoSchema.split(Pattern.quote("."));
        String headersJson = new String(Base64.getDecoder().decode(parts[0].getBytes()));
        String claimsJson = new String(Base64.getDecoder().decode(parts[1].getBytes()));

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> jwtHeader = objectMapper.readValue(headersJson, Map.class);
        Map<String, String> claims = objectMapper.readValue(claimsJson, Map.class);

        JwtToken jwtToken = new JwtToken();
        jwtToken.headers.putAll(jwtHeader);
        jwtToken.claims.putAll(claims);
        jwtToken.signature = Base64.getDecoder().decode(parts[2]);
        return jwtToken;
    }

}
