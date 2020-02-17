package crypto.teste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;

public class InformationReceiver {
    private static final String PROVEDOR="BC";
    private static final String TEXTO_CLARO="0726";
    //    private static final String CRIPTOGRAMA_CABAL = "C0FEDFA28CDFF45D";
    private static final String CRIPTOGRAMA_CABAL ="5C7C7E19052B4115";
    private static final String CHAVE="7589562139513574";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            //Inicializando o cifrador
            Cipher c = Cipher.getInstance("DES", PROVEDOR);

            //Gerando a chave secreta
            SecretKeySpec key = new SecretKeySpec(Hex.decode(CHAVE), "DES");

            //Decriptando o arquivo
            File arq1 = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCryptoX.txt");
            FileInputStream input1 = new FileInputStream(arq1);
            byte[] conteudo1 = new byte[(int) arq1.length()];

            input1.read(conteudo1);

            input1.close();

            File outputCrypto2 = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCryptoXY.txt");
            FileOutputStream output2 = new FileOutputStream(outputCrypto2);

            c.init(Cipher.DECRYPT_MODE, key);
//            output2.write(c.doFinal(Base64.decode(conteudo1)));
            output2.write(c.doFinal(conteudo1));

            output2.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
