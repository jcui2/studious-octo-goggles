package zkLedger;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

import zkLedger.OrProof.OrProofIndex;


public class ProofOfAsset{
    private final OrProof proofOfRecommit;
    private final RangeProof rangeProof;
    
    public ProofOfAsset(Ledger ledger, Asset asset, Bank bank, 
                        BigInteger[] secretMessage, 
                        ECPoint cm, ECPoint token, ECPoint cmPrime, ECPoint tokenPrime, BigInteger recommitValue, BigInteger rPrime,
                        OrProofIndex knownRecommitType) {
        ECPoint cmSumOverCmPrime =ledger.getCachedCM(asset, bank).add(cm).add(cmPrime.negate());
        ECPoint tokenSumOverTokenPrime = ledger.getCachedToken(asset, bank).add(token).add(tokenPrime.negate());
        Function<BigInteger[], ECPoint[]> homomorphismTotal = (inputTuple) -> new ECPoint[] {cmSumOverCmPrime.multiply(inputTuple[0])};
        Function<BigInteger[], ECPoint[]> homomorphismSingle = (inputTuple) -> new ECPoint[] {(Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[1])),
                                                                (Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[2]))};
        
        this.proofOfRecommit = new OrProof(knownRecommitType, secretMessage, homomorphismTotal, homomorphismSingle, 
                                           new ECPoint[] {tokenSumOverTokenPrime}, new ECPoint[] {cm, cmPrime},
                                           new ECPoint[] {cmSumOverCmPrime}, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}, 
                                           knownRecommitType == OrProofIndex.FIRST ? 3 : 1, 9);
        this.rangeProof = new RangeProof(recommitValue, rPrime);
        
    }
    
    public boolean verifyProof(Ledger ledger, Asset asset, Bank bank,ECPoint cm, ECPoint token, ECPoint cmPrime, ECPoint tokenPrime) {
        ECPoint cmSumOverCmPrime =ledger.getCachedCM(asset, bank).add(cm).add(cmPrime.negate());
        ECPoint tokenSumOverTokenPrime = ledger.getCachedToken(asset, bank).add(token).add(tokenPrime.negate());
        Function<BigInteger[], ECPoint[]> homomorphismTotal = (inputTuple) -> new ECPoint[] {cmSumOverCmPrime.multiply(inputTuple[0])};
        Function<BigInteger[], ECPoint[]> homomorphismSingle = (inputTuple) -> new ECPoint[] {(Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[1])),
                                                                (Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[2]))};
        boolean recommitResult =  this.proofOfRecommit.verifyProof(homomorphismTotal, homomorphismSingle,
                                         new ECPoint[] {tokenSumOverTokenPrime}, new ECPoint[] {cm, cmPrime}, new ECPoint[] {cmSumOverCmPrime}, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}, 9);
        boolean rangeResult = this.rangeProof.VerifyProof(cmPrime);
        
        if (!rangeResult) {
            System.out.println(bank+" range error");
        }
        
        if ( !recommitResult) {
            System.out.println(bank+" recommit error");
        }
        
        return recommitResult 
                && rangeResult;
        
    }
    
    
}
