package crypto.teste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class InformationReceiver {
    private static final String PROVEDOR="BC";
    private static final String ALGORITMO_CIFRADOR="DESede/CBC/PKCS5Padding";
//    private static final String DIR_ENTRADA="/home/pedro/IdeaProjects/crypto-teste/src/main/resources/Files/saida/ArquivoCrypto.txt";
    private static final String DIR_ENTRADA="/home/pedro/Downloads/Legendas/testeLegendaX.txt";
//    private static final String DIR_SAIDA="/home/pedro/IdeaProjects/crypto-teste/src/main/resources/Files/saida/ArquivoCryptoRec.txt";
    private static final String DIR_SAIDA="/home/pedro/Downloads/Legendas/testeLegendaXY.txt";
    private static final String DIR_CHAVE_PRIVADA_REC="/home/pedro/IdeaProjects/crypto-teste/src/main/resources/Keys/private_key_receiver.pem";
    private static final String DIR_CHAVE_PUBLIC_SENDER="/home/pedro/IdeaProjects/crypto-teste/src/main/resources/Keys/public_key_sender.der";
    private static final String ALGORITMO_ASSINATURA="SHA256withRSAandMGF1";
    private static final String ALGORITMO_ASSIMETRICO="RSA";
    private static final String ALGORITMO_MD="SHA-256";
    private static final String ALGORITMO_MAC="DESedemac";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            //Inicializando o cifrador
            Cipher c = Cipher.getInstance(ALGORITMO_CIFRADOR, PROVEDOR);

            //Decriptando o arquivo
            File arq1 = new File(DIR_ENTRADA);
            FileInputStream input1 = new FileInputStream(arq1);
            BufferedReader buff = new BufferedReader(new InputStreamReader(input1));

            //Lendo Header e preenchendo dados de validação.
            String header = buff.readLine();
            String identEnc = header.substring(1, 7);
            String identFile = header.substring(7, 17);
            String headerSize = header.substring(17,20);
            String encSecretKey = header.substring(20, 364);
            String encHash = header.substring(364, 408);
            String encMac = header.substring(408);

            if (header.getBytes(Charset.defaultCharset()).length != Integer.parseInt(headerSize)) {
                throw new Exception("O tamanho do header está diferente do descrito na linha");
            }

            //Lendo detalhe encriptado do arquivo
            String detail = buff.readLine();

            buff.close();
            input1.close();

            //Iniciando parametrização para verificação de assinatura e do hash
            AsymmtetricCrypto acrypto = new AsymmtetricCrypto();
            SymmetricCrypto crypto = new SymmetricCrypto();

            byte[] privateKeyReceiver = getRSAPrivateKey(new File(DIR_CHAVE_PRIVADA_REC));
            byte[] publicKeySender = getRSAPublicKey(new File(DIR_CHAVE_PUBLIC_SENDER));

            //Validando e decriptando
            if (validateSignatureFromTag(publicKeySender, privateKeyReceiver, encSecretKey, detail, encMac) && validateHash(detail, encHash)) {
                crypto.decryptFile(detail.getBytes(), new File(DIR_SAIDA), Base64.toBase64String(acrypto.decryptKey(privateKeyReceiver, encSecretKey)));
            } else {
                throw new Exception("Não foi possível decriptar o arquivo pois houveram problemas com as validações");
            }
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

    private static boolean validateSignatureFromTag (byte[] publicKey, byte[] privateKey, String secretKey, String encryptedData, String encrytedSign) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, SignatureException {
        //Calculando a tag da mensagem de autenticação de conteúdo
        AsymmtetricCrypto acrypto = new AsymmtetricCrypto();

        SecretKeySpec sks = new SecretKeySpec(acrypto.decryptKey(privateKey, secretKey),ALGORITMO_MAC);
        Mac mac = Mac.getInstance(ALGORITMO_MAC, PROVEDOR);
        mac.init(sks);
        byte[] tag = mac.doFinal(Base64.decode(encryptedData));

        Signature signature = Signature.getInstance(ALGORITMO_ASSINATURA, PROVEDOR);
        signature.initVerify(KeyFactory.getInstance(ALGORITMO_ASSIMETRICO).generatePublic(new X509EncodedKeySpec(Base64.decode(publicKey))));
        signature.update(tag);

        return signature.verify(Base64.decode(encrytedSign));
    }

    private static boolean validateHash (String encryptedData, String encryptedHash) throws NoSuchProviderException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(ALGORITMO_MD, PROVEDOR);
        md.reset();
        return MessageDigest.isEqual(md.digest(Base64.decode(encryptedData)), Base64.decode(encryptedHash));
    }
}
