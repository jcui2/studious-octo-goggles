package zkLedger;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import zkLedger.OrProof.OrProofIndex;

public class Entry {
    private Bank bank;
    private ECPoint cm;
    private ECPoint token;
    private ECPoint cmPrime;
    private ECPoint tokenPrime;
    private ProofOfAsset poa;
    private ProofOfConsistency poc;
    private Asset asset;
    
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
     * @return true if and only if poa and poc are both true
     */
    public boolean verify(Ledger ledger) {
        boolean pocResult  = poc.verifyProof(new ECPoint[] {cm, token}, new ECPoint[] {cmPrime, tokenPrime}) ;        
        boolean poaResult = poa.verifyProof(ledger, asset, bank, cm, token, cmPrime, tokenPrime);        
        return pocResult && poaResult;
                 
                                   //note this method currently can only be used to prove when this transactions is being created (i.e. cache not updated yet)
                
    }
    
    public ECPoint getCM() {
        return this.cm;
    }
    
    public ECPoint getToken() {
        return this.token;
    }
    

}
