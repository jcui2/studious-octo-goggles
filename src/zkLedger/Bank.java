package zkLedger;

import java.math.BigInteger;
import java.util.Map;

import org.bouncycastle.math.ec.ECPoint;

public class Bank {
        //do banks need their own cache of commits for different assets if they can all access the cache in the 
        // ledger?
        //private BigInteger secretKey; --> banks save their secret key somewhere?
        private ECPoint publicKey;
        
        
        
        public Bank(BigInteger secretKey) {
            //this.secretKey = SECP256K1.getRandomBigInt();
            this.publicKey = Ledger.GENERATOR_H.multiply(secretKey);
        }
        
        /**
         * @return the public key of this bank
         */
        public ECPoint getPublicKey() {
            return this.publicKey;
        }
        
//        public BigInteger totalAsset(Asset asset) {
//            throw new RuntimeException("Not Imeplemtned");
//        
//        }
        
//        public ECPoint getCachedCm(Asset asset) {
//            throw new RuntimeException("Not Implemented Yet");
//        }
//        
//        public ECPoint getCachedToken(Asset asset) {
//            throw new RuntimeException("Not Implemented Yet");
//        }
//    
    
}
