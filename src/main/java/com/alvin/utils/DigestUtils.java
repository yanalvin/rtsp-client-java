package com.alvin.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * Created by alvin on 2020/10/12.
 */
public class DigestUtils {

    private final static Logger LOGGER = LoggerFactory.getLogger(DigestUtils.class);

    private static final String CHARACTERS = "ABCDEF1234567890";

    private final static String NC = "00000001";

    public static String digest(String username, String password, String realm, String nonce, String qop, String cnonce,
                                String uri, String method) {
        //HA1 = MD5("usarname:realm:password");
        //HA2 = MD5("httpmethod:uri");
        //response = MD5("HA1:nonce:nc:cnonce:qop:HA2");
        if (cnonce == null) {
            cnonce = DigestUtils.randomString(32);
        }
        String ha1 = md5sums(username + ":" + realm + ":" + password);
        String ha2 = md5sums(method + ":" + uri);
        String reponse = md5sums(ha1 + ":" + nonce + ":" + NC + ":" + cnonce + ":" + qop + ":" + ha2);
        StringBuffer strBuffer = new StringBuffer();
        strBuffer.append("Digest username=\"");
        strBuffer.append(username);
        strBuffer.append("\",realm=\"");
        strBuffer.append(realm);
        strBuffer.append("\",qop=\"");
        strBuffer.append(qop);
        strBuffer.append("\",algorithm=\"MD5\"");
        strBuffer.append(",uri=\"");
        strBuffer.append(uri);
        strBuffer.append("\",nonce=\"");
        strBuffer.append(nonce);
        strBuffer.append("\",nc=" + NC + ",cnonce=\"");
        strBuffer.append(cnonce);
        strBuffer.append("\",response=\"");
        strBuffer.append(reponse);
        strBuffer.append("\"");
        return strBuffer.toString();
    }

    public static String md5sums(String input) {
        //拿到一个MD5转换器（如果想要SHA1加密参数换成"SHA1"）
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("MD5计算异常", e);
        }
        //输入的字符串转换成字节数组
        byte[] inputByteArray = input.getBytes();
        //inputByteArray是输入字符串转换得到的字节数组
        messageDigest.update(inputByteArray);
        //转换并返回结果，也是字节数组，包含16个元素
        byte[] resultByteArray = messageDigest.digest();
        //字符数组转换成字符串返回
        return byteArrayToHex(resultByteArray);
    }

    public static String byteArrayToHex(byte[] byteArray) {
        //首先初始化一个字符数组，用来存放每个16进制字符
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        //new一个字符数组，这个就是用来组成结果字符串的（解释一下：一个byte是八位二进制，也就是2位十六进制字符）
        char[] resultCharArray = new char[byteArray.length * 2];
        //遍历字节数组，通过位运算（位运算效率高），转换成字符放到字符数组中去
        int index = 0;
        for (byte b : byteArray) {
            resultCharArray[index++] = hexDigits[b >>> 4 & 0xf];
            resultCharArray[index++] = hexDigits[b & 0xf];
        }
        //字符数组组合成字符串返回
        return new String(resultCharArray);
    }

    public static String randomString(int length) {
        Random random = new Random(System.currentTimeMillis());
        char[] text = new char[length];
        for (int i = 0; i < length; i++) {
            text[i] = CHARACTERS.charAt(random.nextInt(CHARACTERS.length()));
        }
        return new String(text);
    }

    public static String encodeBase64(String message){
        return Base64.encodeBase64String(message.getBytes());
    }

    public static String getFileMD5(File file) {
        FileInputStream fileInputStream = null;
        try {
            MessageDigest MD5 = MessageDigest.getInstance("MD5");
            fileInputStream = new FileInputStream(file);
            byte[] buffer = new byte[8192];
            int length;
            while ((length = fileInputStream.read(buffer)) != -1) {
                MD5.update(buffer, 0, length);
            }
            return new String(Hex.encodeHex(MD5.digest()));
        } catch (Exception e) {
            LOGGER.error("计算文件MD5异常", e);
            return null;
        } finally {
            try {
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            } catch (IOException e) {
                LOGGER.error("", e);
            }
        }
    }

}
