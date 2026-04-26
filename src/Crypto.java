import javax.crypto.Cipher;
import java.security.*;

public class Crypto {

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.genKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error generando el par de claves: " + ex.getMessage());
            return null;
        }
    }

    public static byte[] encrypt(byte[] data, PublicKey publicKey) {
        try {
            javax.crypto.KeyGenerator kgen = javax.crypto.KeyGenerator.getInstance("AES");
            kgen.init(128);
            javax.crypto.SecretKey aesKey = kgen.generateKey();

            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedData = aesCipher.doFinal(data);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.WRAP_MODE, publicKey);
            byte[] encryptedKey = rsaCipher.wrap(aesKey);

            byte[] result = new byte[4 + encryptedKey.length + encryptedData.length];
            result[0] = (byte) (encryptedKey.length >> 24);
            result[1] = (byte) (encryptedKey.length >> 16);
            result[2] = (byte) (encryptedKey.length >> 8);
            result[3] = (byte) (encryptedKey.length);
            System.arraycopy(encryptedKey, 0, result, 4, encryptedKey.length);
            System.arraycopy(encryptedData, 0, result, 4 + encryptedKey.length, encryptedData.length);

            return result;

        } catch (Exception ex) {
            System.err.println("Error cifrando los datos: " + ex.getMessage());
            return null;
        }
    }

    public static byte[] decrypt(byte[] encryptedPacket, PrivateKey privateKey) {
        try {
            int keyLength = ((encryptedPacket[0] & 0xFF) << 24)
                    | ((encryptedPacket[1] & 0xFF) << 16)
                    | ((encryptedPacket[2] & 0xFF) << 8)
                    |  (encryptedPacket[3] & 0xFF);

            byte[] encryptedKey = new byte[keyLength];
            byte[] encryptedData = new byte[encryptedPacket.length - 4 - keyLength];
            System.arraycopy(encryptedPacket, 4, encryptedKey, 0, keyLength);
            System.arraycopy(encryptedPacket, 4 + keyLength, encryptedData, 0, encryptedData.length);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.UNWRAP_MODE, privateKey);
            javax.crypto.SecretKey aesKey = (javax.crypto.SecretKey) rsaCipher.unwrap(
                    encryptedKey, "AES", Cipher.SECRET_KEY);

            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            return aesCipher.doFinal(encryptedData);

        } catch (Exception ex) {
            System.err.println("Error descifrando los datos: " + ex.getMessage());
            return null;
        }
    }
}