package crypto.teste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.Charset;
import java.security.Security;

public class SymmetricCrypto {
    private static final String PROVEDOR="BC";
    private static final String TEXTO_CLARO="1234";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try{
            //Inicializando o cifrador
            Cipher c = Cipher.getInstance("DESede", PROVEDOR);

            //Gerando a chave secreta
            KeyGenerator keygen = KeyGenerator.getInstance("DESede", PROVEDOR);
            keygen.init(192);
            SecretKey key = keygen.generateKey();

            //Criptografando a mensagem
            System.out.println("Mensagem antes da criptografia: "+TEXTO_CLARO);
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] criptograma = c.doFinal(TEXTO_CLARO.getBytes());

            System.out.println("Criptograma: "+ DatatypeConverter.printBase64Binary(criptograma));
            System.out.println("Criptograma: "+ DatatypeConverter.printHexBinary(criptograma));

            //Decriptando o criptograma
            c.init(Cipher.DECRYPT_MODE, key);
            System.out.println("Mensagem após a criptografia: "+ new String(c.doFinal(criptograma), Charset.defaultCharset()));
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
