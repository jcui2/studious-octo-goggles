package zkLedger;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.math.ec.ECPoint;

public class Test {

//    public static void main(String[] args) {
        
//        //add at runtime the Bouncy Castle Provider
//        //the provider is available only for this application
//        Security.addProvider(new BouncyCastleProvider());
// 
//        //BC is the ID for the Bouncy Castle provider;
//        if (Security.getProvider("BC") == null){
//            System.out.println("Bouncy Castle provider is NOT available");
//        }
//        else{
//            System.out.println("Bouncy Castle provider is available");
//        }
//    }
    
//        public static void main(String[] args) {
//            //test the API by creating an AES cipher
//        //  in CBC mode with padding
//            BlockCipher engine = new AESEngine();
//            PaddedBufferedBlockCipher encryptCipher;
//            encryptCipher = new PaddedBufferedBlockCipher(
//            new CBCBlockCipher(engine));
//        }
        
        
        
        public static void main(String[] args){
            ECPoint g = Ledger.GENERATOR_G;
            ECPoint h = Ledger.GENERATOR_H;
            ECPoint gTimesp = g.multiply(SECP256K1.P);
            ECPoint hTimesp = h.multiply(SECP256K1.P);
            ECPoint gPlush = g.add(h);
            
            System.out.println(g.isValid());
            System.out.println(h.isValid());
            System.out.println(gTimesp.isInfinity());
            System.out.println(hTimesp.isInfinity());
            System.out.println(gPlush.isInfinity());         

//            try {
//                ByteArrayOutputStream bf = new ByteArrayOutputStream();
//                ObjectOutputStream oos = new ObjectOutputStream(bf);
//                oos.writeObject(point);
//                oos.close();
//
//                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bf.toByteArray()));
//                Object o = ois.readObject();
//                System.out.println(o.toString());
//            } catch (Exception e) {
//                System.out.println("Not exactly Serializable");
//                e.printStackTrace();
//            }

        }
}
