package zkLedger;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

import zkLedger.OrProof.OrProofIndex;

//public class ProofOfAsset {
//    private SigmaProtocol recommitOfAssetReceived; //proof that cm' is recommitment of v_i
//    private SigmaProtocol recommitOfTotalAsset; //proof that cm' is recommitment of sum of all v_i
//    private Function<BigInteger[], ECPoint[]> homomorphismSingle;
//    private Function<BigInteger[], ECPoint[]> homomorphismTotal;
//    private ECPoint cmSumOverCmPrime;
//    private ECPoint tokenSumOverTokenPrime;
//
//    
//    //One of the proofs from above is simulated
//    //TODO rangeProof
//    
//    
//    public ProofOfAsset(Ledger ledger, Asset asset, Bank bank, 
//                        BigInteger[] secretMessage, 
//                        ECPoint cm, ECPoint token, ECPoint cmPrime, ECPoint tokenPrime) {
//        this.cmSumOverCmPrime =ledger.getCachedCM(asset, bank).add(cm).add(cmPrime.negate());
//        this.tokenSumOverTokenPrime = ledger.getCachedToken(asset, bank).add(token).add(tokenPrime.negate());
//        this.homomorphismTotal = (inputTuple) -> new ECPoint[] {cmSumOverCmPrime.multiply(inputTuple[0])};
//        this.homomorphismSingle = (inputTuple) -> new ECPoint[] {(Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[1])),
//                                                                 (Ledger.GENERATOR_G.multiply(inputTuple[0])).add(Ledger.GENERATOR_H.multiply(inputTuple[2]))};
//        
//        if (secretMessage.length == 1) {
//            this.recommitOfAssetReceived = SigmaProtocol.simulateProtocol(homomorphismSingle, new ECPoint[] {cm, cmPrime}, SECP256K1.getRandomBigInt(),
//                                           new BigInteger[] {SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt()});
//            BigInteger[] firstMessagePreimage = new BigInteger[] {SECP256K1.getRandomBigInt()};
//            ECPoint[] firstMessage = homomorphismTotal.apply(firstMessagePreimage);
//            
//
//            BigInteger randomness = allInputToRandomness(new ECPoint[][] {firstMessage, new ECPoint[] {tokenSumOverTokenPrime}, new ECPoint[] {cmSumOverCmPrime},
//                                                         recommitOfAssetReceived.getFirstMessage(), new ECPoint[] {cm, cmPrime}, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}});
//           this.recommitOfTotalAsset = new SigmaProtocol(homomorphismTotal, randomness.subtract(recommitOfAssetReceived.getRandomness()), secretMessage,firstMessagePreimage);
//                  
//           
//        }else if (secretMessage.length == 3) {
//            this.recommitOfTotalAsset = SigmaProtocol.simulateProtocol(homomorphismTotal, new ECPoint[] {tokenSumOverTokenPrime}, SECP256K1.getRandomBigInt(), new BigInteger[] {SECP256K1.getRandomBigInt()});
//
//            BigInteger[] firstMessagePreimage = new BigInteger[] {SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt(), SECP256K1.getRandomBigInt()};
//            ECPoint[] firstMessage = homomorphismSingle.apply(firstMessagePreimage);
//
//            BigInteger randomness = allInputToRandomness(new ECPoint[][] {recommitOfTotalAsset.getFirstMessage(), new ECPoint[] {tokenSumOverTokenPrime}, new ECPoint[] {cmSumOverCmPrime},
//                                                         firstMessage, new ECPoint[] {cm, cmPrime}, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}});
//           this.recommitOfAssetReceived = new SigmaProtocol(homomorphismSingle, randomness.subtract(recommitOfTotalAsset.getRandomness()), secretMessage, firstMessagePreimage);
//        }else {
//            throw new RuntimeException("Secret Not in Domain");
//        }
//    }
//    
//    
//    
//    private static BigInteger allInputToRandomness(ECPoint[][] allInputs) {  //stream better?? NOT SFB at all right now :/
//        ECPoint[] allInputFlattened = new ECPoint[9];
//        int destination = 0;
//        for (ECPoint[] ecPointArray: allInputs) {
//            System.arraycopy(ecPointArray, 0, allInputFlattened, destination, ecPointArray.length);
//            destination += ecPointArray.length;
//        }
//        
//        
//        
//        return SECP256K1.ecPointArrayToRandomness(allInputFlattened);
//    }
//    
//
//    /**
//     * 
//     * @param commitRecommitTuple
//     * @param tokenSumDivTokenPrime
//     * @return
//     */
//    public boolean verifyProof(ECPoint[] commitRecommitTuple, ECPoint[] tokenSumDivTokenPrime) {
//        boolean recommitOfAmountReceived = recommitOfAssetReceived.verifyProof(homomorphismSingle, recommitOfAssetReceived.getRandomness(), commitRecommitTuple);
//        boolean recommitOfTotal = recommitOfTotalAsset.verifyProof(homomorphismTotal, recommitOfTotalAsset.getRandomness(), tokenSumDivTokenPrime);
//        boolean randomnessEquals = (recommitOfAssetReceived.getRandomness().add(recommitOfTotalAsset.getRandomness())).equals(
//                allInputToRandomness(new ECPoint[][] {recommitOfTotalAsset.getFirstMessage(), tokenSumDivTokenPrime, new ECPoint[] {this.cmSumOverCmPrime}, 
//                    recommitOfAssetReceived.getFirstMessage(), commitRecommitTuple, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}}));
//       if (! (recommitOfAmountReceived && recommitOfTotal && randomnessEquals)) {
//        System.out.println("recommitOfAmountReceived "+ recommitOfAmountReceived + "\n recommitOfTotal "+ recommitOfTotal+
//                "\n randomnessEquals "+ randomnessEquals);
//       }
//       
//       
//       
//        return recommitOfAmountReceived && recommitOfTotal && randomnessEquals;
//                
//    }
//    
//
//}

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
