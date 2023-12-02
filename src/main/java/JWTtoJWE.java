import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class JWTtoJWE {

    public static void main(String[] args) throws Exception {
        // Agrega el proveedor Bouncy Castle
        Security.addProvider(new BouncyCastleProvider());

        // Genera un par de claves RSA para firmar y encriptar
        KeyPair keyPair = generateRSAKeyPair();

        // Crea un JWT firmado
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("0001")
                .issuer("JoseZegarra")
                .expirationTime(new Date(System.currentTimeMillis() + 60 * 1000)) // 1 minute
                .build();

        // Firma el JWT con la clave privada
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        JWSSigner signer = new RSASSASigner(rsaPrivateKey);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        signedJWT.sign(signer);

        // Convierte el JWT a bytes
        byte[] jwtBytes = signedJWT.serialize().getBytes("UTF-8");

        // Crea un JWE
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                        .contentType("JWT") // Indica que el contenido es un JWT
                        .build(),
                new Payload(jwtBytes));

        // Encripta el contenido del JWE con la clave pública
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAEncrypter encrypter = new RSAEncrypter(rsaPublicKey);
        jweObject.encrypt(encrypter);

        // Obtiene el resultado final como una cadena
        String jweString = jweObject.serialize();
        System.out.println("JWE: " + jweString);

        // Imprime la representación de la clave privada (NO hacer esto en producción)
        System.out.println("Private Key: " + rsaPrivateKey);

        String privateKey = "Clave privada: " + rsaPrivateKey.getModulus().toString(16);
        System.out.println(privateKey);

    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
