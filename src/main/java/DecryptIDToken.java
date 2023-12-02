import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;

import java.io.BufferedReader;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class DecryptIDToken {

    private final static String PRIVATE_KEY =
 "-----BEGIN PRIVATE KEY-----" +
         "d6fcb6100707d31a5547deaabd8b837f40ce3162a77ca3994caca476138ac5688f661ba3166d78e571c0d8266981af8922e4199ac6d3bf0d844a93c1f2a1824a52ca101e23ce875e48abc8521b2d95a8c84be8d5a16b08b2abeb8fa980e5701a77e88f74492687c0797d32c1765be3385da26788399b01e0ff04ab92c2e2e5bbe75364ada712b9565d002daf6bee08680a94729a1c5d53863682720bef388545f60a4da1d6621ae8812d70a38e6e0e4f66fbb225d35f389c2593f362f803335e31e282842a2d894aaff8d100a87d8533fafc0626be4d1b667f1cc4e26e6f7a6cda2620b1a262e5a693947195ba2a4925dd7d8cae44633642dfdb4ad93c8f7b7f" +
         "-----END PRIVATE KEY-----";



    public static void main(String[] args) throws Exception {

        // Read in the key into a String
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(PRIVATE_KEY));
        String line;
        while ((line = rdr.readLine()) != null) {
            pkcs8Lines.append(line);
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace
        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");

        // Base64 decode the result using java.util.Base64
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);

        // Extract the private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        System.out.println(privKey);

        String encryptedJWTString = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.jSuni7HiEGMSsu_R2ZRal1n2gKbWTUzmhqNc4CExgCDy_k-2OGWW8zjPj6JmBliXThODqueNyWOPE7LIRcJbJE3a2LyLE4sQQeXuvgfcDBkJ9-VNX7knauBQtp42S4xUxetrfG5ibZNGPjJgPF8Do7z5G-YLz8VeHg7-n2549mCNO3uNeCUzU34ETJqbJ9RUENc5BrvXGaL5lVvztj0XXvVPbJiWlRF11H3S32eE3zOlrsRPPXClBd4IIsuR_JQZizZ8FHxr9bjXIiEesCoEpEnPbp1kSPiICUaK2rSZs4OwvRAyB4mSdgMz5qFalHMCisMSMWTUF80OPTRCFZm2jw.tsB726SVr8odFeJT.S6RmuAE4F9Jz8qqDaQYFpjw-kNTsuOosoLAkamx1jUzp0y7UigPUBKW5J1FSE2vvsZd2hTTTQOeyfOzN-xhuZ4PzpRHWkFNg6FCOxaVZKTmgy16q2f-Y041b6E8tRVOw6dfRqZtVsQ6Bh1R6DXXpQcWlua_QoZcQjQhCljexKpisnFJyQxeUlz1uhRJXaYkagG3rMm-GJG3yUlv7dGr_kFAI3RAVa9Q0RtuUw-AY4N_gl81fXmqH_BczOtDgF0CSWuZZ1ALrpo01jjUHUKJSrn0iO9WPaxGQ1stWTk6c1SF01PBsB-DScu0FtjSAXNESZGPPAnWjHJCIpoMhd35i4qNlp54KkErfmtWp4GP8Di6mc_ngXCH9ISaoOWC6jxx37pYbZqCluKZ6E3e6V3szISiAQR6_KqTxLX5VnU3ExVw5hDzlhAe6BWzBFV10IvgV-KrgV-Ss6qYiZit8f7JoC8u3OPqujl4y3M5Zc4o_Nw_r4Q5tqcCNUE60TMXcNt1jFB6ra71hvuxVv6eq6qrW1-_DqAVZe_I8An3Pro_u05X69Pv6sNOrIzlc07T4cDER.FUPDu4N0r5XAMWg3h1sLnw";
        EncryptedJWT jwt = EncryptedJWT.parse(encryptedJWTString);

        // Create a decrypter with the specified private RSA key.
        RSADecrypter decrypter = new RSADecrypter(privKey);

        jwt.decrypt(decrypter);

        // Printing decrypted id token header.
        System.out.println("ID token header: " + jwt.getHeader().toJSONObject());

        // Printing decrypted id token header.
        System.out.println("ID token claims: " + jwt.getJWTClaimsSet().toJSONObject());
    }
}
