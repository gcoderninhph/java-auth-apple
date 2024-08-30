package com.example.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class DemoApplication {

    RestTemplate restTemplate = new RestTemplate();

    Map<String, String> env = new HashMap<>();

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    public static PublicKey createPublicKey(String modulus, String exponent) throws Exception {
        // Chuyển đổi chuỗi modulus và exponent từ base64url thành BigInteger
        BigInteger mod = new BigInteger(1, java.util.Base64.getUrlDecoder().decode(modulus));
        BigInteger exp = new BigInteger(1, java.util.Base64.getUrlDecoder().decode(exponent));

        // Tạo RSAPublicKeySpec từ modulus và exponent
        RSAPublicKeySpec spec = new RSAPublicKeySpec(mod, exp);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Tạo PublicKey từ RSAPublicKeySpec
        return keyFactory.generatePublic(spec);
    }

    @Autowired
    private ObjectMapper objectMapper;

    @PostConstruct
    public void login() throws Exception {
        String token = "eyJraWQiOiJwZ2duUWVOQ09VIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoibmd4LnBvY2tldC5pc2xhbmQubW9uc3Rlci5nbyIsImV4cCI6MTcyNTAwOTI2MywiaWF0IjoxNzI0OTIyODYzLCJzdWIiOiIwMDAxMjUuYTA5MmI4ZTY5NTUxNGE4MjhmNzJmMDQ4Nzc5MGYzN2EuMTA1MyIsImNfaGFzaCI6IkY5N1NXRHk5Zk5NSlN4YVFBMktYdUEiLCJlbWFpbCI6Ik5lZ2F4eXRlc3RAaWNsb3VkLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdXRoX3RpbWUiOjE3MjQ5MjI4NjMsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.AR_PD_dvwcW8i5EDoQJ_QrFwmtzV_T77CRczq3VPhfCAxVIGHySdn-UWua_KbqIe34Cl5ETnYISYr_Xmavc0TBeTu5NQQS9jbbTgBfkMxgtXg4g8tB82Ic8iThnQRpN1DSz5_O5AEmv0a-DHA93KdeJ0aZFagh9D-_BpvPe1inB-QtQaLOG8Tx4pgAtnxE7cVETQIckR0Lb-mlcFHu3drFQlztuFzSglLa3PZSLDKUREHVFpV-MUFsxgKtz6bfMg2nLASxxWiCEpsIibPql1DVcBdChKBbWqvDh5qDkIu9_wD3MvQiO0Bqe9_kte1QXmO6urr1B98u-iC4eImrywXg";

        KeysApple root = restTemplate.getForObject("https://appleid.apple.com/auth/keys", KeysApple.class);
        root.keys.forEach(key -> {
            env.put(key.kid, key.n);
        });

        // Split the token into its parts
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            System.out.println("Invalid JWT token");
            return;
        }

        // Decode base64url encoded header and payload
        TokenHeader header = objectMapper.readValue(Base64.getUrlDecoder().decode(parts[0]), TokenHeader.class);
        TokenBody payload = objectMapper.readValue(Base64.getUrlDecoder().decode(parts[1]), TokenBody.class);

        String publicKeyString = env.get(header.kid);

        PublicKey publicKey = createPublicKey(publicKeyString, "AQAB");

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        System.out.println(claims);
    }


    public static class Key {
        public String kty;
        public String kid;
        public String use;
        public String alg;
        public String n;
        public String e;
    }

    public static class KeysApple {
        public ArrayList<Key> keys;
    }

    public static class TokenBody {
        public String iss;
        public String aud;
        public int exp;
        public int iat;
        public String sub;
        public String c_hash;
        public String email;
        public boolean email_verified;
        public int auth_time;
        public boolean nonce_supported;
    }

    public static class TokenHeader {
        public String kid;
        public String alg;
    }


}
