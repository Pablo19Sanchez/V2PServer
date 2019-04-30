/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package main.android;

import at.favre.lib.crypto.HKDF;
import db.MySQLData;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author pablo
 */
public class MessageHandler extends Thread {
    
    private final DatagramPacket packet;
    private final MySQLData sql = new MySQLData();
    private byte[] encKey, authKey;
    
    public MessageHandler(DatagramPacket packet){
        this.packet = packet;
    }
    
    public void checkMessage(){   
        byte[] messageBits = packet.getData();
        String message = Base64.getEncoder().withoutPadding().encodeToString(messageBits);
        String [] messageReceived = message.split("END");
        System.out.println("Message Received: " + messageReceived[0]);
        String [] statements = messageReceived[0].split("SEP");
        if(sql.checkSession(statements[1]) && statements[0].equals("WARNING")){
            String key = sql.getKey(statements[1]);
            String iv = sql.getIV(statements[1]);
            deriveKeys(key);
            String macCheck = statements[0] + "SEP" + statements[1] + "SEP" + statements[2];
            if(checkMacMessage(macCheck, statements[3],iv)){
                String decryptedMessage = decryptMessage(statements[2],iv);
                System.out.println("Decrypted Info: " + decryptedMessage);
            } else {
                System.out.println("Bad MAC Authentication. Message Rejected");
            }
            
        } else {
            System.out.println("Bad message or wrong session ID. Message rejected");
        }
    } 
    
    private String decryptMessage(String message, String ivString){
        String decryptString = null;
        try {
            byte[] messageBits = Base64.getDecoder().decode(message);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(Base64.getDecoder().decode(ivString))); 
            decryptString = new String(cipher.doFinal(messageBits), "UTF-8");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(MessageHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return decryptString;
    }
    
    private Boolean checkMacMessage(String check, String receivedMAC, String iv){
        byte[] ivByte = Base64.getDecoder().decode(iv);
        SecretKey macKey = new SecretKeySpec(authKey, "HmacSHA256");
        Mac hmac = null;
        try {
            hmac = Mac.getInstance("HmacSHA256");
            hmac.init(macKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            Logger.getLogger(MessageHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        hmac.update(ivByte);
        byte[] macGen = hmac.doFinal(check.getBytes(Charset.forName("UTF-8")));
        String generatedMAC = Base64.getEncoder().withoutPadding().encodeToString(macGen);
        return true;
    }
    
    private SecretKey getKey(String session){
        MySQLData db = new MySQLData();
        String keyString = db.getKey(session);
        SecretKey macKey = new SecretKeySpec(keyString.getBytes(), 0, keyString.getBytes().length, "HmacSHA256");
        return macKey;
    }
    
    private void deriveKeys(String key){
        byte[] keyBytes = Base64.getDecoder().decode(key);
        encKey = HKDF.fromHmacSha256().expand(keyBytes, "encKey".getBytes(Charset.forName("UTF-8")), 16);
        authKey = HKDF.fromHmacSha256().expand(keyBytes, "authKey".getBytes(Charset.forName("UTF-8")), 32); //HMAC-SHA256 key is 32 byte
    }
}
