package zkLedger;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import zkLedger.OrProof.OrProofIndex;

/**
 * immutable class representing one entry in a transaction 
 */
public class Entry {
    private final Bank bank;
    private final ECPoint cm;
    private final ECPoint token;
    private final ECPoint cmPrime;
    private final ECPoint tokenPrime;
    private final ProofOfAsset poa;
    private final ProofOfConsistency poc;
    private final Asset asset;
    
    /**
     * construct an Entry object representing the entry for one bank in one transaction
     * @param ledger the ledger for which the transaction takes place
     * @param asset the Asset in which the transaction takes place 
     * @param bank the Bank corresponding to this entry
     * @param amountReceived the amount received by this bank in this transaction, can be either positive, negative or zeros
     * @param r the randomness to be used to generate a commit
     * @param recommitValue the value to recommit to, must be nonnegative
     * @param rPrime the randomness to be used to generate a recommit
     * @param poaSecretMessage the secret message for proof of asset
     * @param knownRecommitType the type of recommit, 
     *        OrProofIndex.FIRST represents recommiting to the total asset, OrProofIndex.SECOND represents recommiting to the amount received in transaction
     */
    public Entry(Ledger ledger, Asset asset, Bank bank, BigInteger amountReceived, BigInteger r, BigInteger recommitValue, BigInteger rPrime,
                  BigInteger[] poaSecretMessage, OrProofIndex knownRecommitType) {
        this.asset = asset;
        this.bank = bank;
        this.cm = Ledger.PEDERSON.apply(new BigInteger[] {amountReceived, r});
        this.cmPrime = Ledger.PEDERSON.apply(new BigInteger[] {recommitValue, rPrime});
        this.token = bank.getPublicKey().multiply(r);
        this.tokenPrime = bank.getPublicKey().multiply(rPrime);
        this.poc = new ProofOfConsistency(new BigInteger[] {amountReceived, r}, 
                                          new BigInteger[] {recommitValue, rPrime},
                                          bank.getPublicKey());
        this.poa = new ProofOfAsset(ledger, asset, bank, 
                                    poaSecretMessage,
                                    cm, token, cmPrime, tokenPrime, recommitValue, rPrime,
                                    knownRecommitType);
    }
    
    
    /**
     * @param ledger the ledger with respect to which this entry needs to be verified
     * @return true if and only both proof of consistency and proof of asset holds for this entry
     */
    public boolean verify(Ledger ledger) {
        boolean pocResult  = poc.verifyProof(new ECPoint[] {cm, token}, new ECPoint[] {cmPrime, tokenPrime}, bank.getPublicKey()) ;        
        boolean poaResult = poa.verifyProof(ledger, asset, bank, cm, token, cmPrime, tokenPrime);        
        return pocResult && poaResult;
        //note this method can only be used to verify a entry when the transactions is just created (i.e. caches in the ledger not updated yet)
                
    }
    
    /**
     * @return the commitment in the entry
     */
    public ECPoint getCM() {
        return this.cm;
    }
    
    /**
     * @return the token in this entry
     */
    public ECPoint getToken() {
        return this.token;
    }
    

}
