package zkLedger;

import java.math.BigInteger;
import java.time.LocalDateTime;

import org.bouncycastle.math.ec.ECPoint;

import zkLedger.OrProof.OrProofIndex;

/**
 * An immutable class representing an entry of deposit
 */
public class DepositEntry {
    private final Asset asset;
    private final Bank bank;
    private final LocalDateTime time;
    private final BigInteger amount; //this class encodes amount in cm but since amount is public information, it is still included in case might be useful
    private final ECPoint cm;
    private final ECPoint token;
    private final ECPoint cmPrime;
    private final ECPoint tokenPrime;
    private final ProofOfAsset proofOfAsset;
    
 
    /**
     * Construct an object representing an entry of deposit
     * @param ledger the ledger for which this entry is generated
     * @param asset the Asset in which the deposit takes place
     * @param time the time for which the deposit happens
     * @param bank the Bank to which the deposit is made 
     * @param amount the amount of Asset asset that is deposited to Bank bank, could be either positive or negative
     * @param receiverTotalAsset the total amount of Asset held by bank after receiving the deposit
     * @param secretKey the secret key of the bank
     */
    public DepositEntry(Ledger ledger, Asset asset, LocalDateTime time, 
                        Bank bank, BigInteger amount, BigInteger receiverTotalAsset, BigInteger secretKey) {
        this.asset = asset;
        this.bank = bank;
        this.amount = amount;
        this.time = time;
        
        BigInteger r = SECP256K1.getRandomBigInt();
        this.cm = Ledger.PEDERSON.apply(new BigInteger[] {amount, r});
        this.token = bank.getPublicKey().multiply(r);
        
        BigInteger rPrime = SECP256K1.getRandomBigInt();
        this.cmPrime = Ledger.PEDERSON.apply(new BigInteger[] {receiverTotalAsset, rPrime});
        this.tokenPrime = bank.getPublicKey().multiply(rPrime);
        this.proofOfAsset = new ProofOfAsset(ledger, asset, bank, new BigInteger[] {secretKey},
                                              cm, token, cmPrime, tokenPrime, receiverTotalAsset, rPrime, OrProofIndex.FIRST);
       
    }
    
    /**
     * @param ledger the ledger with respect to which this entry needs to be verified 
     * @return true if and only if the bank receiving the deposit will end up having a non-negative amount of that asset
     */
    public boolean verifyProof(Ledger ledger) {
        boolean assetCorrectness = proofOfAsset.verifyProof(ledger, this.asset, this.bank, 
                this.cm, this.token, this.cmPrime, this.tokenPrime);
        return  assetCorrectness;
    }
    
    /**
     * @return the commitment of this entry
     */
    public ECPoint getCM() {
        return this.cm;
    }

    /**
     * @return the token of this entry
     */
    public ECPoint getToken() {
        return this.token;
    }
    
    /**
     * @return the asset this deposit takes place in
     */
    public Asset getAsset() {
        return this.asset;
    }
    
    /**
     * @return the bank receiving the deposit
     */
    public Bank getBank() {
        return this.bank;
    }

    
}
