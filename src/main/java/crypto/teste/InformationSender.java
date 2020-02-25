package crypto.teste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

public class InformationSender {
    private static final String PROVEDOR="BC";
    private static final String ALGORITMO_CIFRADOR="DESede/CBC/PKCS5Padding";
    private static final String ALGORITMO_SIMETRICO="DESede";
//    private static final String DIR_ENTRADA="/home/pedro/IdeaProjects/crypto-teste/src/main/resources/Files/temp/ArquivoCrypto.txt";
    private static final String DIR_ENTRADA="/home/pedro/Downloads/Legendas/testeLegenda.txt";
//    private static final String DIR_SAIDA="/home/pedro/IdeaProjects/crypto-teste/src/main/resources/Files/saida/ArquivoCrypto.txt";
    private static final String DIR_SAIDA="/home/pedro/Downloads/Legendas/testeLegendaX.txt";
    private static final String DIR_CHAVE_PRIVADA_SENDER="/home/pedro/IdeaProjects/crypto-teste/src/main/resources/Keys/private_key_sender.pem";
    private static final String DIR_CHAVE_PUBLIC_REC="/home/pedro/IdeaProjects/crypto-teste/src/main/resources/Keys/public_key_receiver.der";
    private static final String ALGORITMO_ASSINATURA="SHA256withRSAandMGF1";
    private static final String ALGORITMO_ASSIMETRICO="RSA";
    private static final String ALGORITMO_MD="SHA-256";
    private static final String ALGORITMO_MAC="DESedemac";
    private static final int KEY_SIZE=192;

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        try{
            //Inicializando o cifrador
            Cipher c = Cipher.getInstance(ALGORITMO_CIFRADOR, PROVEDOR);

            //Gerando a chave secreta
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITMO_SIMETRICO);
            keyGen.init(KEY_SIZE);
            SecretKey key = keyGen.generateKey();

            SymmetricCrypto crypto = new SymmetricCrypto();

            String content = crypto.encryptFileToText(new File(DIR_ENTRADA), Base64.toBase64String(key.getEncoded()));

            //Calculando Hash
            MessageDigest md = MessageDigest.getInstance(ALGORITMO_MD, PROVEDOR);
            md.reset();
            byte[] hash = md.digest(Base64.decode(content));

            //Calculando MAC
            SecretKeySpec sks = new SecretKeySpec(key.getEncoded(), ALGORITMO_MAC);
            Mac mac = Mac.getInstance(ALGORITMO_MAC, PROVEDOR);
            mac.init(sks);
            byte[] tag = mac.doFinal(Base64.decode(content));

            AsymmtetricCrypto acrypto = new AsymmtetricCrypto();

            //Assinando a mensagem de autenticação
            byte[] publicKeyReceiver = getRSAPublicKey(new File(DIR_CHAVE_PUBLIC_REC));
            byte[] privateKeySender = getRSAPrivateKey(new File(DIR_CHAVE_PRIVADA_SENDER));
            Signature signature = Signature.getInstance(ALGORITMO_ASSINATURA, PROVEDOR);
            signature.initSign(KeyFactory.getInstance(ALGORITMO_ASSIMETRICO).generatePrivate(new PKCS8EncodedKeySpec(privateKeySender)), new SecureRandom());
            signature.update(tag);
            byte[] sign = signature.sign();

            //Montagem de linha de header
            StringBuilder header = new StringBuilder();

            header.append("ENCFLCB");
            header.append(String.format("%1$"+10+"s", "ARQCRYPTO"));
            header.append("752");
            header.append(Base64.toBase64String(acrypto.encryptKey(publicKeyReceiver, Base64.toBase64String(key.getEncoded()))));
            header.append(Base64.toBase64String(hash));
            header.append(Base64.toBase64String(sign));

            String linha = header.toString();

            System.out.println("HEADER: "+linha);

            File fin = new File(DIR_SAIDA);

            FileOutputStream outputStream = new FileOutputStream(fin);
            outputStream.write(linha.getBytes(Charset.defaultCharset()));
            outputStream.write("\n".getBytes(Charset.defaultCharset()));
            outputStream.write(content.getBytes(Charset.defaultCharset()));
            outputStream.close();

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static byte[] getRSAPublicKey(File f) throws IOException {
        FileInputStream i = new FileInputStream(f);
        byte[] content = new byte[(int) f.length()];
        i.read(content);

        return Base64.encode(content);
    }

    private static byte[] getRSAPrivateKey(File f) throws IOException {
        FileInputStream i = new FileInputStream(f);
        byte[] content = new byte[(int) f.length()];
        i.read(content);

        String strKey = new String(content, Charset.defaultCharset());
        strKey = strKey.replace("\n","");
        strKey = strKey.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        strKey = strKey.replace("-----END RSA PRIVATE KEY-----", "");

        return Base64.decode(strKey);
    }

    private static void debugKey(Key key) throws IOException {
        FileOutputStream out = new FileOutputStream(new File("/home/pedro/IdeaProjects/crypto-teste/src/main/resources/Keys/secretKey"));
        out.write(Base64.encode(key.getEncoded()));
        out.close();
    }
}
