package crypto.teste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            //Encriptação com a chave pública
            System.out.println("Encriptando a mensagem: "+TEXTO_CLARO);
            c.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), OEAPps);
            byte[] criptograma = c.doFinal(TEXTO_CLARO.getBytes());

            System.out.println(new String(criptograma, "UTF-8"));

            System.out.println("Encriptando o arquivo: ");
            File arquivoClaro = new File("/resources/ArquivoCrypto.txt");
            FileInputStream leitura = new FileInputStream(arquivoClaro);
//            leitura.readAllBytes();
//            File arquivoEncriptado = new File("/resources/ArquivoCryptoX.txt");
//            FileOutputStream escrita = new FileOutputStream(arquivoEncriptado);
//            escrita.write(c.doFinal(leitura.readAllBytes()));

            //Decriptando a mensagem com a chave privada
            c.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), OEAPps);
            byte[] textoDecifrado = c.doFinal(criptograma);
            System.out.println("Mensagem após a decriptação: "+new String(textoDecifrado, "UTF-8"));
        } catch (Exception e){
            System.out.print("Erro ao inicializar o gerador de chaves: "+e.getMessage());
            e.printStackTrace();
        }
    }

    public byte[] encryptKey(byte[] secretKey, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());

        //Configurações de parametrização OEAP
        OAEPParameterSpec OEAPps = new OAEPParameterSpec("SHA-256",
                "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher c = Cipher.getInstance("RSA/None/OAEPwithSHA256andMGF1Padding", PROVEDOR);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        c.init(Cipher.ENCRYPT_MODE, factory.generatePublic(new X509EncodedKeySpec(Base64.decode(secretKey))), OEAPps);

        return c.doFinal(Base64.decode(key));
    }

    public byte[] decryptKey(byte[] secretKey, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());

        //Configurações de parametrização OEAP
        OAEPParameterSpec OEAPps = new OAEPParameterSpec("SHA-256",
                "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher c = Cipher.getInstance("RSA/None/OAEPwithSHA256andMGF1Padding", PROVEDOR);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        c.init(Cipher.DECRYPT_MODE, factory.generatePrivate(new PKCS8EncodedKeySpec(secretKey)), OEAPps);

        return c.doFinal(Base64.decode(key));
    }

    public byte[] decryptSignature(byte[] key, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());

        //Configurações de parametrização OEAP
        OAEPParameterSpec OEAPps = new OAEPParameterSpec("SHA-256",
                "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher c = Cipher.getInstance("RSA/None/OAEPwithSHA256andMGF1Padding", PROVEDOR);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        c.init(Cipher.DECRYPT_MODE, factory.generatePublic(new X509EncodedKeySpec(Base64.decode(key))), OEAPps);

        return c.doFinal(signature);
    }

    public byte[] encryptSignature(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());

        //Configurações de parametrização OEAP
        OAEPParameterSpec OEAPps = new OAEPParameterSpec("SHA-256",
                "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher c = Cipher.getInstance("RSA/None/OAEPwithSHA256andMGF1Padding", PROVEDOR);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        c.init(Cipher.ENCRYPT_MODE, factory.generatePrivate(new PKCS8EncodedKeySpec(key)), OEAPps);

        return c.doFinal(data);
    }
}
