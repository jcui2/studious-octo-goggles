package zkLedger;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

import zkLedger.OrProof.OrProofIndex;

/**
 * An immutable class representing a proof of asset
 */
public class ProofOfAsset{
    private final OrProof proofOfRecommit;
    private final RangeProof rangeProof;
    
    /**
     * Construct a proof of asset 
     * @param ledger the ledger for which the proof of asset is generated
     * @param asset the Asset in which this is proving the amount
     * @param bank the Bank that this is proving the commitment amount
     * @param secretMessage an array of BigIntegers representing either [secret key] or [amount receive, r, r']
     * @param cm commitment associated with this 
     * @param token token associated with this 
     * @param cmPrime recommitment associated with this
     * @param tokenPrime token for recommitment associated with this 
     * @param recommitValue the value cm' is committing to
     * @param rPrime the randomness used in cm'
     * @param knownRecommitType an index indicating whether cm' is a recommit to total asset or a recommit to the amount received
     */
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
    
    /**
     * Verify that a proof of asset is correct 
     * @param ledger the ledger with respect to which the proof is verified 
     * @param asset the Asset for which this is proving the amount 
     * @param bank the Bank that this is proving the commitment amount
     * @param cm commitment expected to be associated with this 
     * @param token token expected to be associated with this 
     * @param cmPrime recommit expected to be associated with this 
     * @param tokenPrime token for recommitment expected to be associated with this 
     * @return true if and only if cm' is either a recommit of cm or a recommit of the total asset held by the band after current transaction,
     *              and cm' is a commitment to a value in range [0, 2^40]
     */
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
