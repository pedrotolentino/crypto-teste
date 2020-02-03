package crypto.teste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;

public class AsymmtetricCrypto {
    private static final String PROVEDOR="BC";
    private static final String TEXTO_CLARO="Essa mensagem é importante!";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            //Configurações de parametrização OEAP
            OAEPParameterSpec OEAPps = new OAEPParameterSpec("SHA-256",
                    "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            Cipher c = Cipher.getInstance("RSA/None/OAEPwithSHA256andMGF1Padding", PROVEDOR);

            //Criação das chaves

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", PROVEDOR);
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();

            //Encriptação com a chave pública
            System.out.println("Encriptando a mensagem: "+TEXTO_CLARO);
            c.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), OEAPps);
            byte[] criptograma = c.doFinal(TEXTO_CLARO.getBytes());

            System.out.println(new String(criptograma, "UTF-8"));

            //Decriptando a mensagem com a chave privada
            c.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), OEAPps);
            byte[] textoDecifrado = c.doFinal(criptograma);
            System.out.println("Mensagem após a decriptação: "+new String(textoDecifrado, "UTF-8"));
        } catch (Exception e){
            System.out.print("Erro ao inicializar o gerador de chaves: "+e.getMessage());
            e.printStackTrace();
        }
    }
}
