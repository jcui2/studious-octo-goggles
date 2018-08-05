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
//    private Ledger ledger;
    private Asset asset;
    
    public Entry(Ledger ledger, Asset asset, Bank bank, BigInteger amountReceived, BigInteger r, BigInteger recommitValue, BigInteger rPrime,
                  BigInteger[] poaSecretMessage, OrProofIndex knownRecommitType) {
        this.asset = asset;
        this.bank = bank;
        this.cm = Ledger.PEDERSON.apply(new BigInteger[] {amountReceived, r});
//        = (Ledger.GENERATOR_G.multiply(amountReceived)).add(Ledger.GENERATOR_H.multiply(r));
        this.cmPrime 
                     = Ledger.PEDERSON.apply(new BigInteger[] {recommitValue, rPrime});
//        = (Ledger.GENERATOR_G.multiply(recommitValue)).add(Ledger.GENERATOR_H.multiply(rPrime));
        this.token = bank.getPublicKey().multiply(r);
        this.tokenPrime = bank.getPublicKey().multiply(rPrime);
        this.poc = new ProofOfConsistency(new BigInteger[] {amountReceived, r}, 
                                          new BigInteger[] {recommitValue, rPrime},
                                          bank.getPublicKey());
        this.poa = new ProofOfAsset(ledger, asset, bank, 
                                    poaSecretMessage,
                                    cm, token, cmPrime, tokenPrime, recommitValue, rPrime,
                                    knownRecommitType);
//        this.ledger = ledger;
        
        
    }
    
    
    /**
     * @return true if and only if poa and poc are both true
     */
    public boolean verify(Ledger ledger) {
        boolean pocResult  = poc.verifyProof(new ECPoint[] {cm, token}, new ECPoint[] {cmPrime, tokenPrime}) ;
//        boolean poaResult = poa.verifyProof(new ECPoint[] {cm, cmPrime}, new ECPoint[] {this.ledger.getCachedToken(this.asset, this.bank).add(token).add(tokenPrime.negate())}); 
        
        boolean poaResult = poa.verifyProof(ledger, asset, bank, cm, token, cmPrime, tokenPrime);
        
        
//        System.out.println(bank+" poc is "+ pocResult + "\n poa is " + poaResult);
        
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
