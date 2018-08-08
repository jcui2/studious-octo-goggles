package zkLedger;

import java.math.BigInteger;
import java.time.LocalDateTime;

import org.bouncycastle.math.ec.ECPoint;

import zkLedger.OrProof.OrProofIndex;

public class DepositEntry {
    private final Asset asset;
    private final Bank bank;
    private final LocalDateTime time;
    private final BigInteger amount;
    private final ECPoint cm;
    private final ECPoint token;
    private final ECPoint cmPrime;
    private final ECPoint tokenPrime;
//    private final RangeProof rangeProof;
    private final ProofOfAsset proofOfAsset;
    
 
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
//        
//        this.rangeProof = new RangeProof(receiverTotalAsset, rPrime);
        
        this.proofOfAsset = new ProofOfAsset(ledger, asset, bank, new BigInteger[] {secretKey},
                                              cm, token, cmPrime, tokenPrime, receiverTotalAsset, rPrime, OrProofIndex.FIRST);
       
    }
    
    
    public boolean verifyProof(Ledger ledger) {
//        boolean rangeCorrectness = rangeProof.VerifyProof(cmPrime);
        boolean assetCorrectness = proofOfAsset.verifyProof(ledger, this.asset, this.bank, 
                this.cm, this.token, this.cmPrime, this.tokenPrime);
        
//        System.out.println("rangeProof "+ rangeCorrectness + "assetProof"+ assetCorrectness);
        return  assetCorrectness;
    }
    
    public ECPoint getCM() {
        return this.cm;
    }

    public ECPoint getToken() {
        return this.token;
    }
    
    public Asset getAsset() {
        return this.asset;
    }
    
    public Bank getBank() {
        return this.bank;
    }

    
}
