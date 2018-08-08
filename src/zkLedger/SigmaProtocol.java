package zkLedger;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.Stream;

import org.bouncycastle.math.ec.ECPoint;

/**
 * an immutable object representing a non-interactive zero-knowledge proof
 */
public class SigmaProtocol {
    private final ECPoint[] firstMessage; //first message of a Sigma protocol
    private final BigInteger[] secondMessage; //second message of a Sigma protocol
    private final BigInteger randomness; 
    
    /**
     * Construct a non-interactive proof that uses sigma protocol and SHA 256 as crypto hash function
     * @param homomorphism a function that maps from the domain containing the secret message to the commitment space
     * @param secretMessage the secret message to be conveyed
     * @param firstMessagePreimage the pre-image for first message 
     * @param additionalInput additional input to the crypto hash function 
     */
    public SigmaProtocol(Function<BigInteger[], ECPoint[]> homomorphism, 
                         BigInteger[] secretMessage,
                         BigInteger[] firstMessagePreimage,
                         ECPoint[] additionalInput) {
        this(homomorphism, 
                inputToRandomness(homomorphism.apply(firstMessagePreimage), homomorphism.apply(secretMessage), additionalInput), 
                secretMessage, firstMessagePreimage);
    }
    
    private static BigInteger inputToRandomness(ECPoint[] firstMessage, ECPoint[] secretImage, ECPoint[] additionalInput) {
        ECPoint[] concatArray = Stream.concat(Stream.concat(Arrays.stream(firstMessage), Arrays.stream(secretImage)), 
                                              Arrays.stream(additionalInput))
                                              .toArray(ECPoint[]::new);
        return SECP256K1.ecPointArrayToRandomness(concatArray);
    }
        
    
    /**
     * Construct a non-interactive proof that uses sigma protocol and a given randomness 
     * @param homomorphism a function that maps from the domain containing the secret message to the commitment space
     * @param randomness a randomly chosen challenge from the challenge space
     * @param secretMessage the secret message to be conveyed
     * @param firstMessagePreimage the pre-image for first message 
     */
    public SigmaProtocol(Function<BigInteger[], ECPoint[]> homomorphism, 
                         BigInteger randomness,
                         BigInteger[] secretMessage,
                         BigInteger[] firstMessagePreimage) {
        this.firstMessage = homomorphism.apply(firstMessagePreimage);
        this.randomness = randomness;
        this.secondMessage = new BigInteger[secretMessage.length];
        for (int i=0; i < secretMessage.length; i++) {
            secondMessage[i] = (firstMessagePreimage[i].add(randomness.multiply(secretMessage[i]))).mod(SECP256K1.P); 
        }
    }
    
    //used to simulate a sigma protocol
    private SigmaProtocol(ECPoint[] firstMessage, BigInteger randomness, BigInteger[] secondMessage) {//defensive copying
        this.firstMessage = Arrays.copyOf(firstMessage, firstMessage.length);
        this.randomness = randomness;
        this.secondMessage = Arrays.copyOf(secondMessage, secondMessage.length);
    }
    
    
   
    /**
     * Simulate a sigma protocol with randomly selected second message and randomness
     * @param homomorphism a function that maps from the domain containing the secret message to the commitment space
     * @param secretImage the expected image of the secret message
     * @param randomness a randomly chosen challenge from the challenge space
     * @param randomSecondMessage the second message to be used in the sigma protocol 
     * @return a simulated simga protocol for which the verifier can prove that the prover knows the preimage of secretImage
     */
    public static SigmaProtocol simulateProtocol(Function<BigInteger[], ECPoint[]> homomorphism, 
                                                 ECPoint[] secretImage,
                                                 BigInteger randomness,
                                                 BigInteger[] randomSecondMessage) {
        ECPoint[] secondMessageImage = homomorphism.apply(randomSecondMessage);
        ECPoint[] firstMessage = new ECPoint[secondMessageImage.length];
        for (int i=0; i < secondMessageImage.length; i++) {
            firstMessage[i] = secondMessageImage[i].add(secretImage[i].multiply(randomness.negate()));
        }
        
        return new SigmaProtocol(firstMessage, randomness, randomSecondMessage);
        
    }

   
    /**
     * Verify that a zero-knowledge proof in the form of Sigma Protocol is correct
     * @param homomorphism a function that maps from the domain containing the secret message to the commitment space
     * @param secretImage the expected image of the secret message
     * @param additionalInput additional input to crypto hash function SHA256
     * @return true if and only if the second message under homomorphism is the same as first message plus secret Image times to the randomness,
     *          where plus is the group operation in the codomain
     */
    public boolean verifyProof(Function<BigInteger[], ECPoint[]> homomorphism, 
                               ECPoint[] secretImage,
                               ECPoint[] additionalInput) {
        BigInteger inputedRandomness = inputToRandomness(this.firstMessage, secretImage, additionalInput); // unsigned
        return this.verifyProof(homomorphism, inputedRandomness, secretImage);
    }
    
    
    /**
     * Verify that a zero-knowledge proof in the form of Sigma Protocol is correct
     * @param homomorphism a function that maps from the domain containing the secret message to the commitment space
     * @param inputedRandomness the randomness expected to be used in the proof
     * @param secretImage the expected image of the secret message
     * @return true if and only if the second message under homomorphism is the same as first message plus secret Image times to the randomness,
     *          where plus is the group operation in the codomain
     */
    public boolean verifyProof(Function<BigInteger[], ECPoint[]> homomorphism, 
                               BigInteger inputedRandomness,
                               ECPoint[] secretImage) {
        ECPoint[] secondMessageImage = homomorphism.apply(this.secondMessage);
        ECPoint[] expectedValue = new ECPoint[this.firstMessage.length];
        for (int i=0; i< this.firstMessage.length; i++) {
            expectedValue[i] = this.firstMessage[i].add(secretImage[i].multiply(inputedRandomness));
            
        }
        
        for (int i = 0; i < expectedValue.length; i++) {
            if (!secondMessageImage[i].equals(expectedValue[i]) ){
                return false;
            }
        }
        
        return true;
    }
    
    
    
    /**
     * @return the randomness used in this 
     */
    public BigInteger getRandomness() {
        return this.randomness;
    }
    
    /**
     * @return the first message associated with this 
     */
    public ECPoint[] getFirstMessage() {
        return this.firstMessage;
    }

}
