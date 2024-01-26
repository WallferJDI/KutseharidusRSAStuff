import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class KutsehariduskeskusRSA {

    public static final String STANDART_PUBLIC_KEY = "65537";
    public static final int CONVERT_MASK = 0xff;
    private final BigInteger publicKey;
    private final BigInteger privateKey;
    private final BigInteger modules;

    public KutsehariduskeskusRSA(BigInteger p, BigInteger q) {
        modules = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        publicKey = new BigInteger(STANDART_PUBLIC_KEY);
        privateKey = publicKey.modInverse(phi);
    }


    public List<BigInteger> encode(String message) {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        List<BigInteger> encryptedBytes = new ArrayList<>();

        for (byte b : bytes) {
            BigInteger byteAsBigInteger = BigInteger.valueOf((int) b & CONVERT_MASK);
            encryptedBytes.add(byteAsBigInteger.modPow(publicKey, modules));
        }

        return encryptedBytes;
    }

    public String decode(List<BigInteger> encodedItems) {
        StringBuilder decrypted = new StringBuilder();

        for (BigInteger encodedItem : encodedItems) {
            byte[] decryptedByte = encodedItem.modPow(privateKey, modules).toByteArray();
            decrypted.append(decryptedByte.length == 2 ? new String(decryptedByte, 1, 1, StandardCharsets.UTF_8) : new String(decryptedByte, StandardCharsets.UTF_8) );
        }

        return decrypted.toString();
    }

    public static void main(String[] args) {
        BigInteger p = new BigInteger("263");
        BigInteger q = new BigInteger("433");

        KutsehariduskeskusRSA rsa = new KutsehariduskeskusRSA(p, q);

        String originalMessage = "Interesting Task, thanks !!";
        System.out.println("originalMessage " + originalMessage);

        List<BigInteger> encryptedMessage = rsa.encode(originalMessage);
        System.out.println("encryptedMessage " + encryptedMessage);

        String decryptedMessage = rsa.decode(encryptedMessage);
        System.out.println("decryptedMessage " + decryptedMessage);
    }
}
