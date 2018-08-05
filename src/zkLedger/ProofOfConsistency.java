package zkLedger;

import java.math.BigInteger;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

public class ProofOfConsistency {
    private SigmaProtocol consistentCommit; //proof that randomness in cm and token are the same
    private SigmaProtocol consistentAuxiliaryCommit; //proof that randomness in cm' and token' are the same
    private Function<BigInteger[], ECPoint[]> homomorphism;
    private final ECPoint[] ADDITIONAL_INPUT = new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H};
    
    
    public ProofOfConsistency(BigInteger[] commit, BigInteger[] recommit, ECPoint publicKey) {
        this.homomorphism = (inputTuple) -> new ECPoint[] {(Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[1])),
                publicKey.multiply(inputTuple[1])};
        
        this.consistentCommit = new SigmaProtocol(homomorphism, commit, 
                new BigInteger[] {SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt()},
                ADDITIONAL_INPUT);
        
        this.consistentAuxiliaryCommit = new SigmaProtocol(homomorphism, recommit, 
                new BigInteger[] {SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt()},
                ADDITIONAL_INPUT);
        
    }
                              
    
//    private static SigmaProtocol consistencyProof(BigInteger randomness, BigInteger commitedValue, ECPoint publicKey) {        
//        Function<BigInteger[], ECPoint[]> homomorphism = (inputTuple) -> new ECPoint[] {(Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[1])),
//                                                                                         publicKey.multiply(inputTuple[1])};
//        return new SigmaProtocol(homomorphism, new BigInteger[] {commitedValue, randomness}, 
//                                 new BigInteger[] {SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt()},
//                                 new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H});
//    }
    
    /**
     * 
     * @param commitPair
     * @param recommitPair
     * @return
     */
    public boolean verifyProof(ECPoint[] commitPair, ECPoint[] recommitPair) {
        boolean cm = consistentCommit.verifyProof(homomorphism, commitPair, ADDITIONAL_INPUT);
        boolean reCm = consistentAuxiliaryCommit.verifyProof(homomorphism, recommitPair, ADDITIONAL_INPUT);
        return  cm && reCm;
                
    }
}
