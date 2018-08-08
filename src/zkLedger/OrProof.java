package zkLedger;

import java.math.BigInteger;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

public class OrProof {
    private SigmaProtocol firstProof;
    private SigmaProtocol secondProof; 
    
    
    public enum OrProofIndex{
        FIRST, SECOND
    }
    
    
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
    
    
    
    private static BigInteger allInputToRandomness(ECPoint[][] allInputs, int length) {  
        ECPoint[] allInputFlattened = new ECPoint[length];
        int destination = 0;
        for (ECPoint[] ecPointArray: allInputs) {
            System.arraycopy(ecPointArray, 0, allInputFlattened, destination, ecPointArray.length);
            destination += ecPointArray.length;
        }
        return SECP256K1.ecPointArrayToRandomness(allInputFlattened);
    }
    


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
