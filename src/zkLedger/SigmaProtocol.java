package zkLedger;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.Stream;

import org.bouncycastle.math.ec.ECPoint;

public class SigmaProtocol {
    private final ECPoint[] firstMessage; //first message of a Sigma protocol
    private final BigInteger[] secondMessage; //second message of a Sigma protocol
    private final BigInteger randomness; 
    
    
    /*TODO: add parameter as needed so that first message can be randomly chosen from domain*/
    /**
     * A constructor that creates a sigma protocol
     * @param homomorphism a function that maps from the domain containing the secret message to the commitment space
     * @param cryptoHash a function that can be used to generate random challenge
     * @param secretMessage the secret message to be conveyed
     * @return a zero-knowledge proof in the format of a sigma protocol
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
//        final ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
//        try {
//            for (ECPoint[] ecPointArray: new ECPoint[][] {firstMessage, secretImage, additionalInput}) {
//                for (ECPoint i: ecPointArray) {
//                    byteArray.write(i.getEncoded(true));
//                }
//            }
//        } catch(Exception e) {
//            e.printStackTrace();
//        }
//        
//        
//        
//        synchronized(SECP256K1.CURVE) {
//            byte[] inputInByte = SECP256K1.SHA256.digest(byteArray.toByteArray());
//            return new BigInteger(1, inputInByte);
//        }
       
        
        ECPoint[] concatArray = Stream.concat(Stream.concat(Arrays.stream(firstMessage), Arrays.stream(secretImage)), 
                                              Arrays.stream(additionalInput))
                                              .toArray(ECPoint[]::new);
        return SECP256K1.ecPointArrayToRandomness(concatArray);
        
        
    }
        
    
    
    /**
     * A constructor of a sigma protocol that simulates a zkp given a expected result
     * @param homomorphism a function that maps from the domain containing the secret message to the commitment space
     * @param randomness a randomly chosen challenge from the challenge space
     * @param secondMessage a randomly chosen secret message from the domain containing the secret message
     * @param imageOfSecret the value that the secret gets mapped to by the homomorphism
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
    
    public SigmaProtocol(ECPoint[] firstMessage, BigInteger randomness, BigInteger[] secondMessage) {//defensive copying
        this.firstMessage = Arrays.copyOf(firstMessage, firstMessage.length);
        this.randomness = randomness;
        this.secondMessage = Arrays.copyOf(secondMessage, secondMessage.length);
    }
    
    
    
    /**
     * Simulate a sigma protocol with randomly selected second message from domain and randomness
     * @param homomorphism
     * @param randomness
     * @param randomSecondMessage
     * @return
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
     * @param imageOfSecret the value that the secret gets mapped to by the homomorphism
     * @return true if and only if the proof is true
     */
    public boolean verifyProof(Function<BigInteger[], ECPoint[]> homomorphism, 
                               ECPoint[] secretImage,
                               ECPoint[] additionalInput) {
        BigInteger inputedRandomness = inputToRandomness(this.firstMessage, secretImage, additionalInput); // unsigned
        return this.verifyProof(homomorphism, inputedRandomness, secretImage);
    }
    
    
    /**
     * Verify using user inputed randomness
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
//                System.out.println(secondMessageImage[i]);
//                System.out.println(expectedValue[i]);
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
    
    
    public ECPoint[] getFirstMessage() {
        return this.firstMessage;
    }

}
