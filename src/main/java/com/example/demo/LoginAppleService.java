package com.example.demo;

import jakarta.annotation.PostConstruct;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
public class LoginAppleService {

    private RestTemplate restTemplate;

    public LoginAppleService(){
        this.restTemplate = new RestTemplate();
    }

    @PostConstruct
    public void init(){
        DataKey key = restTemplate.getForObject("https://appleid.apple.com/auth/keys", DataKey.class);
        System.out.println(key.keys.get(0).n);
    }

    private static class Key{
        public String kty;
        public String kid;
        public String use;
        public String alg;
        public String n;
        public String e;
    }

    private static class DataKey{
        public List<Key> keys;
    }

    public record AppleToken(List<String> auth, Map<String, Object> claimsMap) { }
    public AppleToken validateToken(String token) throws InvalidJwtException, MalformedClaimException {
        HttpsJwks httpsJkws = new HttpsJwks("https://appleid.apple.com/auth/keys");

        HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(httpsJwksKeyResolver)
                .setExpectedIssuer("https://appleid.apple.com")
                .setExpectedAudience(token).build();

        JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        List<String> auth = jwtClaims.getAudience();
        Map<String, Object> claimsMap = jwtClaims.getClaimsMap();
        return new AppleToken(auth, claimsMap);
    }

}
