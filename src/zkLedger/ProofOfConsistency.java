package zkLedger;

import java.math.BigInteger;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

/**
 * A immutable object proving that cm and cm' are consistent with their respective tokens
 */
public class ProofOfConsistency {
    private final SigmaProtocol consistentCommit; //proof that randomness in cm and token are the same
    private final SigmaProtocol consistentAuxiliaryCommit; //proof that randomness in cm' and token' are the same
    private final ECPoint[] ADDITIONAL_INPUT = new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H};
    
    /**
     * Construct a ProofOfConsistency object 
     * @param commit an array containing cm
     * @param recommit an array containing cm'
     * @param publicKey public key of the bank associated with cm and cm'
     */
    public ProofOfConsistency(BigInteger[] commit, BigInteger[] recommit, ECPoint publicKey) {
        Function<BigInteger[], ECPoint[]> homomorphism = (inputTuple) -> new ECPoint[] {(Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[1])),
                publicKey.multiply(inputTuple[1])};
        
        this.consistentCommit = new SigmaProtocol(homomorphism, commit, 
                new BigInteger[] {SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt()},
                ADDITIONAL_INPUT);
        
        this.consistentAuxiliaryCommit = new SigmaProtocol(homomorphism, recommit, 
                new BigInteger[] {SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt()},
                ADDITIONAL_INPUT);
        
    }
                              
    
    /**
     * @param commitPair [cm, token]
     * @param recommitPair [cm', token']
     * @param publicKey the public key of the bank associated with cm, token, cm' and token'
     * @return true if and only if [cm, token] use the same randomness and [cm', token'] use the same randomness
     */
    public boolean verifyProof(ECPoint[] commitPair, ECPoint[] recommitPair, ECPoint publicKey) {
        Function<BigInteger[], ECPoint[]> homomorphism = (inputTuple) -> new ECPoint[] {(Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[1])),
                publicKey.multiply(inputTuple[1])};
        boolean cm = consistentCommit.verifyProof(homomorphism, commitPair, ADDITIONAL_INPUT);
        boolean reCm = consistentAuxiliaryCommit.verifyProof(homomorphism, recommitPair, ADDITIONAL_INPUT);
        return  cm && reCm;
                
    }
}
