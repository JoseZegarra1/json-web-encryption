import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

public class RSAPrivateKeyToPEM {

    public static void main(String[] args) throws Exception {
        // Genera un par de claves RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Obtiene la clave privada del par de claves
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        // Convierte la clave privada a formato PEM
        String pemPrivateKey = convertToPEM(rsaPrivateKey);

        // Imprime la clave privada en formato PEM
        System.out.println(pemPrivateKey);
    }

    private static String convertToPEM(PrivateKey privateKey) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (PEMWriter pemWriter = new PEMWriter(stringWriter)) {
            pemWriter.writeObject(privateKey);
        }
        return stringWriter.toString();
    }
}
