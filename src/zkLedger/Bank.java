package zkLedger;

import java.math.BigInteger;
import java.util.Map;

import org.bouncycastle.math.ec.ECPoint;

/**
 * immutable object representing a bank
 *
 */
public class Bank {
        private final ECPoint publicKey;

        public Bank(BigInteger secretKey) {
            this.publicKey = Ledger.GENERATOR_H.multiply(secretKey);
        }
        
        /**
         * @return the public key of this bank
         */
        public ECPoint getPublicKey() {
            return this.publicKey;
        }
        
        //inherits referential equality and hash code form object class
    
}
