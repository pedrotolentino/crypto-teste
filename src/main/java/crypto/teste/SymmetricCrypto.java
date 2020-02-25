package crypto.teste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

public class SymmetricCrypto {
    private static final String PROVEDOR="BC";
    private static final String TEXTO_CLARO="0726";
//    private static final String CRIPTOGRAMA_CABAL = "C0FEDFA28CDFF45D";
//    private static final String CRIPTOGRAMA_CABAL ="5C7C7E19052B4115";
    private static final String CRIPTOGRAMA ="jasbabPDifFqX+OMjf5BQXfwAWj+PEgGOp9xFO/dx2is3uuz/j+kYQ==";
    private static final String CHAVE="3PidUt+12iwgBBqh0yxivA==";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try{
            //Inicializando o cifrador
            Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding", PROVEDOR);

            //Gerando a chave secreta
            SecretKeySpec key = new SecretKeySpec(Base64.decode(CHAVE), "DESede");

//            System.out.println("SENHA: "+TEXTO_CLARO);

            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(getIV(key)));

            System.out.println("DESede");
//            System.out.println(Base64.toBase64String(c.doFinal(TEXTO_CLARO.getBytes(Charset.defaultCharset()))));
            System.out.println(new String(c.doFinal(Base64.decode(CRIPTOGRAMA))));

//            DESKeySpec keySpec = new DESKeySpec(Hex.decode(CHAVE));
//            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
//            SecretKey key = factory.generateSecret(keySpec);

            //Criptografando a mensagem
//            System.out.println("Mensagem antes da criptografia: "+TEXTO_CLARO);

//            File arq = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCrypto.txt");
//            FileInputStream input = new FileInputStream(arq);
//            byte[] conteudo = new byte[(int) arq.length()];
//
//            input.read(conteudo);
//
//            input.close();
//
//            c.init(Cipher.ENCRYPT_MODE, key);
//            byte[] criptograma = c.doFinal(conteudo);
//
//            System.out.println("Criptograma: "+ Base64.toBase64String(criptograma));
//            System.out.println("Criptograma: "+ Hex.toHexString(criptograma));
//
//            File outputCrypto = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCryptoX.txt");
//            FileOutputStream output = new FileOutputStream(outputCrypto);
//
////            output.write(Base64.encode(criptograma));
//            output.write(criptograma);
//
//            output.close();

            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//            File arq1 = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCryptoX.txt");
//            FileInputStream input1 = new FileInputStream(arq1);
//            byte[] conteudo1 = new byte[(int) arq1.length()];
//
//            input1.read(conteudo1);
//
//            input1.close();
//
//            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//            File outputCrypto2 = new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/ArquivoCryptoXY.txt");
//            FileOutputStream output2 = new FileOutputStream(outputCrypto2);
//
//            c.init(Cipher.DECRYPT_MODE, key);
////            output2.write(c.doFinal(Base64.decode(conteudo1)));
//            output2.write(c.doFinal(conteudo1));
//
//            output2.close();

            //Decriptando o criptograma
//            c.init(Cipher.DECRYPT_MODE, key);
//            System.out.println("Mensagem após a criptografia: "+ new String(c.doFinal(criptograma), Charset.defaultCharset()));

//            System.out.println("Criptograma Cabal: "+new String(c.doFinal(Hex.decode(CRIPTOGRAMA_CABAL)), Charset.defaultCharset()));
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void encryptFile(File input, File output, String key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        FileInputStream inputStream = new FileInputStream(input);
        byte[] inputByte = new byte[(int) input.length()];
        inputStream.read(inputByte);
        inputStream.close();

        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding", PROVEDOR);
        SecretKeySpec secretkey = new SecretKeySpec(Base64.decode(key), "DESede");
        c.init(Cipher.ENCRYPT_MODE, secretkey, new IvParameterSpec(getIV(secretkey)));

        FileOutputStream outputStream = new FileOutputStream(output);
        outputStream.write(Base64.encode(c.doFinal(inputByte)));
        outputStream.close();

//        System.out.println(Base64.toBase64String(c.doFinal(inputByte)));
//        System.out.println("IV: "+c.getIV());
    }

    public String encryptFileToText(File input, String key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        FileInputStream inputStream = new FileInputStream(input);
        byte[] inputByte = new byte[(int) input.length()];
        inputStream.read(inputByte);
        inputStream.close();

        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding", PROVEDOR);
        SecretKeySpec secretkey = new SecretKeySpec(Base64.decode(key), "DESede");
        c.init(Cipher.ENCRYPT_MODE, secretkey, new IvParameterSpec(getIV(secretkey)));

        return Base64.toBase64String(c.doFinal(inputByte));
    }

    public void decryptFile(byte[] input, File output, String key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding", PROVEDOR);
        byte[] keyData =  Base64.decode(key);
//        byte[] iv = new byte[8];
//
//        for (int i = 0; i < iv.length; i++) {
//            iv[i] = keyData[i];
//        }

        SecretKeySpec secretkey = new SecretKeySpec(keyData, "DESede");
        c.init(Cipher.DECRYPT_MODE, secretkey, new IvParameterSpec(getIV(secretkey)));

        FileOutputStream outputStream = new FileOutputStream(output);
        outputStream.write(c.doFinal(Base64.decode(input)));
        outputStream.close();

//        System.out.println("IV: "+c.getIV());
    }

    private static byte[] getIV(Key key) {
        byte[] iv = new byte[8];

        for (int i = 0; i < iv.length; i++)
            iv[i] = key.getEncoded()[i];
        return iv;
    }
}
