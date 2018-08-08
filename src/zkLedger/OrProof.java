package zkLedger;

import java.math.BigInteger;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

/**
 * an immutable class representing a or proof of two statements
 *
 */
public class OrProof {
    private SigmaProtocol firstProof;
    private SigmaProtocol secondProof; 
    
    /**
     * the types of the statement the secret of which is known to the prover
     */
    public enum OrProofIndex{
        FIRST, SECOND
    }
    
    /**
     * Construct a or proof of two statements
     * @param knownProof the index of the statement, the secret of which is actually known to the prover
     * @param secretMessage the secret message to be proved 
     * @param firstHomomorphism the homomorphism associated with first statement 
     * @param secondHomomorphism the homomorphism associated with second statement 
     * @param firstSecretImage the expected image of the secret message for first statement 
     * @param secondSecretImage the expected image of the secret message for second statement 
     * @param firstAdditionalInfo additional input used in first statement (used to generate randomness for non-interactive proof)
     * @param secondAdditionalInfo additional input used in second statement 
     * @param simulatedProofPreimageLength the number of sets in the domain (seen as a cross-product of sets) for the proof that is simulated
     * @param numberOfHashArguments number of arguments send to the crypto hash function to generate randomness (usualy the sum of all inputs for both proofs)
     */
    public OrProof(OrProofIndex knownProof, BigInteger[] secretMessage, 
                   Function<BigInteger[], ECPoint[]> firstHomomorphism, Function<BigInteger[], ECPoint[]> secondHomomorphism,
                   ECPoint[] firstSecretImage, ECPoint[] secondSecretImage,
                   ECPoint[] firstAdditionalInfo, ECPoint[] secondAdditionalInfo,
                   int simulatedProofPreimageLength,
                   int numberOfHashArguments) {
        
        BigInteger[] randomSecondMessage = new BigInteger[simulatedProofPreimageLength];  //random second message for the unknown proof
        for (int i=0; i < simulatedProofPreimageLength; i++) {
            randomSecondMessage[i] = SECP256K1.getRandomBigInt();
        }
        
        BigInteger[] randomFirstMessagePreimage = new BigInteger[secretMessage.length];
        for (int i=0; i < secretMessage.length; i++) {
            randomFirstMessagePreimage[i] = SECP256K1.getRandomBigInt();
        }
        
        
        ECPoint[] firstMessage;
        BigInteger totalRandomness;
        
        switch(knownProof) {
        case FIRST:
            this.secondProof = SigmaProtocol.simulateProtocol(secondHomomorphism, secondSecretImage, 
                                                                            SECP256K1.getRandomBigInt(), randomSecondMessage);
            firstMessage = firstHomomorphism.apply(randomFirstMessagePreimage);
            totalRandomness = allInputToRandomness(new ECPoint[][] {firstMessage, firstSecretImage, firstAdditionalInfo, 
                                                                                secondProof.getFirstMessage(), secondSecretImage, secondAdditionalInfo}, numberOfHashArguments);
            this.firstProof = new SigmaProtocol(firstHomomorphism, totalRandomness.subtract(secondProof.getRandomness()), secretMessage, randomFirstMessagePreimage);
            return;
       
        case SECOND:
            
            this.firstProof = SigmaProtocol.simulateProtocol(firstHomomorphism, firstSecretImage, 
                    SECP256K1.getRandomBigInt(), randomSecondMessage);
            firstMessage = secondHomomorphism.apply(randomFirstMessagePreimage);
            totalRandomness = allInputToRandomness(new ECPoint[][] {firstProof.getFirstMessage(), firstSecretImage, firstAdditionalInfo, 
                firstMessage, secondSecretImage, secondAdditionalInfo}, numberOfHashArguments);
            this.secondProof = new SigmaProtocol(secondHomomorphism, totalRandomness.subtract(firstProof.getRandomness()), secretMessage, randomFirstMessagePreimage);
            return;
            
        }
    }
    
    
    /**
     * @param allInputs An array of all inputs, order as follows: 
     *        first statement first message, first statement expected image of the secret, first statement additional information,
     *        second statement first message, second statement expected image of the secret, second statement additional information,  
     * @param length the number of ECPoints sent as input for both proofs 
     * @return a Big Integer as a result of applying the hash function to all inputs
     */
    private static BigInteger allInputToRandomness(ECPoint[][] allInputs, int length) {  
        ECPoint[] allInputFlattened = new ECPoint[length];
        int destination = 0;
        for (ECPoint[] ecPointArray: allInputs) {
            System.arraycopy(ecPointArray, 0, allInputFlattened, destination, ecPointArray.length);
            destination += ecPointArray.length;
        }
        return SECP256K1.ecPointArrayToRandomness(allInputFlattened);
    }
    

    /**
     * verify that the or proof is correct 
     * @param firstHomomorphism the homomorphism associated with first statement 
     * @param secondHomomorphism the homomorphism associated with second statement 
     * @param firstSecretImage the expected image of the secret message for first statement 
     * @param secondSecretImage the expected image of the secret message for second statement 
     * @param firstAdditionalInfo additional input used in first statement
     * @param secondAdditionalInfo additional input used in second statement 
     * @param numberOfHashArguments number of arguments send to the crypto hash function to generate randomness
     * @return true if and only is both statements are true and the sum of the randomness sums up to expectation
     */
    public boolean verifyProof(Function<BigInteger[], ECPoint[]> firstHomomorphism, Function<BigInteger[], ECPoint[]> secondHomomorphism,
                               ECPoint[] firstSecretImage, ECPoint[] secondSecretImage,
                               ECPoint[] firstAdditionalInfo, ECPoint[] secondAdditionalInfo, int numberOfHashArguments) {
        boolean firstResult = firstProof.verifyProof(firstHomomorphism, firstProof.getRandomness(), firstSecretImage);
        boolean secondResult = secondProof.verifyProof(secondHomomorphism, secondProof.getRandomness(), secondSecretImage);
        boolean consistentRandomness = (firstProof.getRandomness().add(secondProof.getRandomness()))
                                         .equals(allInputToRandomness(new ECPoint[][] {firstProof.getFirstMessage(), firstSecretImage, firstAdditionalInfo,
                                             secondProof.getFirstMessage(), secondSecretImage, secondAdditionalInfo}, numberOfHashArguments));
        return firstResult && secondResult && consistentRandomness;
                
    }
    
    
    
}
