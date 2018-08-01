package zkLedger;

import java.math.BigInteger;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

public class ProofOfAsset {
    private SigmaProtocol recommitOfAssetReceived; //proof that cm' is recommitment of v_i
    private SigmaProtocol recommitOfTotalAsset; //proof that cm' is recommitment of sum of all v_i
    private Function<BigInteger[], ECPoint[]> homomorphismSingle;
    private Function<BigInteger[], ECPoint[]> homomorphismTotal;
    private ECPoint cmSumOverCmPrime;
    private ECPoint tokenSumOverTokenPrime;
    //One of the proofs from above is simulated
    //TODO rangeProof
    
    
    public ProofOfAsset(Ledger ledger, Asset asset, Bank bank, 
                        BigInteger[] secretMessage, 
                        ECPoint cm, ECPoint token, ECPoint cmPrime, ECPoint tokenPrime) {
        this.cmSumOverCmPrime =ledger.getCachedCM(asset, bank).add(cm).add(cmPrime.negate());
        this.tokenSumOverTokenPrime = ledger.getCachedToken(asset, bank).add(token).add(tokenPrime.negate());
        this.homomorphismTotal = (inputTuple) -> new ECPoint[] {cmSumOverCmPrime.multiply(inputTuple[0])};
        this.homomorphismSingle = (inputTuple) -> new ECPoint[] {(Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[1])),
                                                                 (Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[2]))};
        
        if (secretMessage.length == 1) {
            this.recommitOfAssetReceived = SigmaProtocol.simulateProtocol(homomorphismSingle, new ECPoint[] {cm, cmPrime}, SECP256K1.getRandomBigInt(),
                                           new BigInteger[] {SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt()});
            BigInteger[] firstMessagePreimage = new BigInteger[] {SECP256K1.getRandomBigInt()};
            ECPoint[] firstMessage = homomorphismTotal.apply(firstMessagePreimage);
            

            BigInteger randomness = allInputToRandomness(new ECPoint[][] {firstMessage, new ECPoint[] {tokenSumOverTokenPrime}, new ECPoint[] {cmSumOverCmPrime},
                                                         recommitOfAssetReceived.getFirstMessage(), new ECPoint[] {cm, cmPrime}, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}});
           this.recommitOfTotalAsset = new SigmaProtocol(homomorphismTotal, randomness.subtract(recommitOfAssetReceived.getRandomness()), secretMessage,firstMessagePreimage);
                  
           
        }else if (secretMessage.length == 3) {
            this.recommitOfTotalAsset = SigmaProtocol.simulateProtocol(homomorphismTotal, new ECPoint[] {tokenSumOverTokenPrime}, SECP256K1.getRandomBigInt(), new BigInteger[] {SECP256K1.getRandomBigInt()});

            BigInteger[] firstMessagePreimage = new BigInteger[] {SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt()};
            ECPoint[] firstMessage = homomorphismSingle.apply(firstMessagePreimage);

            BigInteger randomness = allInputToRandomness(new ECPoint[][] {recommitOfTotalAsset.getFirstMessage(), new ECPoint[] {tokenSumOverTokenPrime}, new ECPoint[] {cmSumOverCmPrime},
                                                         firstMessage, new ECPoint[] {cm, cmPrime}, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}});
           this.recommitOfAssetReceived = new SigmaProtocol(homomorphismSingle, randomness.subtract(recommitOfTotalAsset.getRandomness()), secretMessage, firstMessagePreimage);
        }else {
            throw new RuntimeException("Secret Not in Domain");
        }
    }
    
    
    
    private static BigInteger allInputToRandomness(ECPoint[][] allInputs) {  //stream better?? NOT SFB at all right now :/
        ECPoint[] allInputFlattened = new ECPoint[9];
        int destination = 0;
        for (ECPoint[] ecPointArray: allInputs) {
            System.arraycopy(ecPointArray, 0, allInputFlattened, destination, ecPointArray.length);
            destination += ecPointArray.length;
        }
        
        return SECP256K1.ecPointArrayToRandomness(allInputFlattened);
    }
    

    /**
     * 
     * @param randomness the sum of the randomness in recommitOfAssetReceived and recommitOfTotalAsset expected
     * @param homomorphism1 a function that maps from the domain containing the secret message showing cm' is recommit of v_i to the commitment space
     * @param imageOfSecret1 the value that the secret gets mapped to by the homomorphism1
     * @param homomorphism2 a function that maps from the domain containing the secret message showing that cm' is recommitment of sum of all v_i to the commitment space
     * @param imageOfSecret2 the value that the secret gets mapped to by the homomorphism2
     * @return true if and only if both recommitOfAssetReceived and recommitOfTotalAsset are true, 
     *         the randomness used in both proofs sums up to expected value, and range proof is true
     */
    public boolean verifyProof(ECPoint[] commitRecommitTuple, ECPoint[] tokenSumDivTokenPrime) {
        boolean recommitOfAmountReceived = recommitOfAssetReceived.verifyProof(homomorphismSingle, recommitOfAssetReceived.getRandomness(), commitRecommitTuple);
        boolean recommitOfTotal = recommitOfTotalAsset.verifyProof(homomorphismTotal, recommitOfTotalAsset.getRandomness(), tokenSumDivTokenPrime);
        boolean randomnessEquals = (recommitOfAssetReceived.getRandomness().add(recommitOfTotalAsset.getRandomness())).equals(
                allInputToRandomness(new ECPoint[][] {recommitOfTotalAsset.getFirstMessage(), tokenSumDivTokenPrime, new ECPoint[] {this.cmSumOverCmPrime}, 
                    recommitOfAssetReceived.getFirstMessage(), commitRecommitTuple, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}}));
       if (! (recommitOfAmountReceived && recommitOfTotal && randomnessEquals)) {
        System.out.println("recommitOfAmountReceived "+ recommitOfAmountReceived + "\n recommitOfTotal "+ recommitOfTotal+
                "\n randomnessEquals "+ randomnessEquals);
       }
       
       
       
        return recommitOfAmountReceived && recommitOfTotal && randomnessEquals;
                
    }
    //call verify of the two proof field, use getRandomness as randomness input. Then add up the randomness to see if
    //in accordance with the one given by hash

}
