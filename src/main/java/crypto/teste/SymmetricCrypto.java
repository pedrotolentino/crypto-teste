package crypto.teste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.security.Security;

public class SymmetricCrypto {
    private static final String PROVEDOR="BC";
    private static final String TEXTO_CLARO="0726";
//    private static final String CRIPTOGRAMA_CABAL = "C0FEDFA28CDFF45D";
    private static final String CRIPTOGRAMA_CABAL ="5C7C7E19052B4115";
    private static final String CHAVE="7589562139513574";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try{
            //Inicializando o cifrador
            Cipher c = Cipher.getInstance("DES", PROVEDOR);

            //Gerando a chave secreta
            SecretKeySpec key = new SecretKeySpec(Hex.decode(CHAVE), "DES");

//            DESKeySpec keySpec = new DESKeySpec(Hex.decode(CHAVE));
//            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
//            SecretKey key = factory.generateSecret(keySpec);

            //Criptografando a mensagem
//            System.out.println("Mensagem antes da criptografia: "+TEXTO_CLARO);

            File arq = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCrypto.txt");
            FileInputStream input = new FileInputStream(arq);
            byte[] conteudo = new byte[(int) arq.length()];

            input.read(conteudo);

            input.close();

            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] criptograma = c.doFinal(conteudo);

            System.out.println("Criptograma: "+ Base64.toBase64String(criptograma));
            System.out.println("Criptograma: "+ Hex.toHexString(criptograma));

            File outputCrypto = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCryptoX.txt");
            FileOutputStream output = new FileOutputStream(outputCrypto);

//            output.write(Base64.encode(criptograma));
            output.write(criptograma);

            output.close();

            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            File arq1 = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCryptoX.txt");
            FileInputStream input1 = new FileInputStream(arq1);
            byte[] conteudo1 = new byte[(int) arq1.length()];

            input1.read(conteudo1);

            input1.close();

            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            File outputCrypto2 = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCryptoXY.txt");
            FileOutputStream output2 = new FileOutputStream(outputCrypto2);

            c.init(Cipher.DECRYPT_MODE, key);
//            output2.write(c.doFinal(Base64.decode(conteudo1)));
            output2.write(c.doFinal(conteudo1));

            output2.close();

            //Decriptando o criptograma
//            c.init(Cipher.DECRYPT_MODE, key);
//            System.out.println("Mensagem após a criptografia: "+ new String(c.doFinal(criptograma), Charset.defaultCharset()));

//            System.out.println("Criptograma Cabal: "+new String(c.doFinal(Hex.decode(CRIPTOGRAMA_CABAL)), Charset.defaultCharset()));
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
