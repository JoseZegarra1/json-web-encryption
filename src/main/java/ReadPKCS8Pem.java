import java.io.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import android.util.Base64;

public class ReadPKCS8Pem {

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
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

        // Base64 decode the result

        byte [] pkcs8EncodedBytes = Base64.decode(pkcs8Pem, Base64.DEFAULT);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        System.out.println(privKey);
    }

}

