/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package main.android;

import java.util.Base64;
import db.MySQLData;
import java.io.*;
import java.security.SecureRandom;
import java.sql.SQLException;
import javax.net.ssl.SSLSocket;


/**
 *
 * @author pablo
 */
public class ClientHandler extends Thread {
    
    private static final String ALPHA_NUMERIC_STRING = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private final SSLSocket clientSocket;
    private BufferedWriter out;
    private BufferedReader in;
    
    private String session, keyUser, iv;
    private final RandomString rs = new RandomString(7);
    private final MySQLData sql = new MySQLData();
    
    public ClientHandler(SSLSocket socket){
        this.clientSocket = socket;
    }
    
    public void connectUser() throws IOException, SQLException {
        System.out.println("Connection established");
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
        String message = in.readLine();
        System.out.println("Message: " + message);
        checkMessage(message);
        in.close();
    }  
    
    private void checkMessage(String message) throws IOException, SQLException{
        String [] statements = message.split("%");
        String answer = " ";
        switch(statements[0]){
            case "HELLO":
                // Obtain the key from the user
                keyUser = statements[1];
                // Generate the session id and the iv
                session = getSessionID();
                iv = getIV();
                // Activate session id with key and IV
                sql.registerSession(session, keyUser, iv);
                // Send back message
                answer = "OK%" + session + "%" + iv + "\n"; 
                out.write(answer);
                break;
            case "BYE":
                session = statements[1];
                sql.removeSession(session);
                answer = "OK\n";
                out.write(answer);
                break;
            default:
                out.write("NOK\n");
                break;
        }
        System.out.println("Answer Sent: " + answer);
        out.flush();
        out.close();
        clientSocket.close();
    }
    
    private String getIV() { 
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivByte = new byte[16];
        secureRandom.nextBytes(ivByte);
        String ivString = Base64.getEncoder().withoutPadding().encodeToString(ivByte);
        return ivString;
    } 
    
    private String getSessionID(){
        int count = 10;
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }
}
