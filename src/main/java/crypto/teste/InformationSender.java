package crypto.teste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;

public class InformationSender {
    private static final String PROVEDOR="BC";
    private static final String TEXTO_CLARO="0726";
    //    private static final String CRIPTOGRAMA_CABAL = "C0FEDFA28CDFF45D";
    private static final String CRIPTOGRAMA_CABAL = "5C7C7E19052B4115";
    private static final String CHAVE="7589562139513574";


    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        try{
            //Inicializando o cifrador
            Cipher c = Cipher.getInstance("DESede", PROVEDOR);

            //Gerando a chave secreta
            SecretKeySpec key = new SecretKeySpec(Hex.decode(CHAVE), "DES");

            //Criptografando a mensagem
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
        }catch (Exception e){

        }
    }

}
