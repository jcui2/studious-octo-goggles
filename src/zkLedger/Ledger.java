package zkLedger;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Mutable class representing a ledger
 */
public class Ledger{
   //generators used in the zkLedger
   public static final ECPoint GENERATOR_G = SECP256K1.makeGeneratorFromString("0");
   public static final ECPoint GENERATOR_H = SECP256K1.makeGeneratorFromString("1");
   
   public static final Function<BigInteger[], ECPoint> PEDERSON = (input) 
                                                                     -> (GENERATOR_G.multiply(input[0])).add(GENERATOR_H.multiply(input[1]));
    
    private final List<Bank> participants; //banks currently participating in transactions
    private final List<Transaction> transactions; 
    private final Map<Asset, List<Transaction>> transactionsByAsset; 
    private final List<DepositEntry> deposits; 
    private final Map<Asset, List<DepositEntry>> depositsByAsset;
    private final Map<Asset, Map<Bank, ECPoint>> cmCache; 
    private final Map<Asset, Map<Bank, ECPoint>> tokenCache;
    private final Clock clock;
    
    
    /**
     * Construct a new ledger with participants currently involved in transactions
     * @param participants banks currently participating in transactions
     */
    public Ledger(List<Bank> participants) {
        this.participants = participants;
        this.transactions = new ArrayList<Transaction>();
        this.transactionsByAsset = new HashMap<Asset, List<Transaction>>();
        this.deposits = new ArrayList<DepositEntry>();
        this.depositsByAsset =  new HashMap<Asset, List<DepositEntry>>();
        this.clock = Clock.systemDefaultZone();
        this.cmCache = new HashMap<Asset, Map<Bank, ECPoint>>();
        this.tokenCache = new HashMap<Asset, Map<Bank, ECPoint>>();
    }
    
    /**
     * Make a Transaction object that can be used to verify this transaction respects the invariants
     * @param asset the type of Asset this transaction takes place in
     * @param senderBank Bank that intends to send money
     * @param receiverBank Bank that supposed to receive money
     * @param amount a positive value of asset in the transaction
     * @param senderTotalAsset total amount of asset sender bank holds after this transaction
     * @param secretKey secret key held by this bank
     * @return a Transaction object representing this transaction
     */
    public synchronized Transaction makeTransaction(Asset asset, Bank senderBank, Bank receiverBank, BigInteger amount,
                                                    BigInteger senderTotalAsset, BigInteger secretKey) {
        LocalDateTime time = LocalDateTime.now(clock);
        Transaction transaction = new Transaction(this, asset, time, senderBank, receiverBank, 
                                                  amount, senderTotalAsset,
                                                  new ArrayList<Bank>(this.participants), secretKey);
        return transaction;
    }
    

    /**
     * Verify that a transaction respects all invariants and append it to the ledger. 
     * A transaction is ignored if it does not pass the verification
     * @param transaction the transaction to be verified
     */
    public synchronized void addTransaction(Transaction transaction) {
         if (!transaction.verify(this)) {
             System.out.println("Proof Error, transacation ignored");
             return;
         }
        
        System.out.println("proof verified, adding transaction to ledger"); 
        
        Asset asset = transaction.getAsset();
         
        transactions.add(transaction);
        if (transactionsByAsset.containsKey(asset)) { 
            transactionsByAsset.get(asset).add(transaction);
       
        }else { 
            List<Transaction> transactionsOfThisAsset = new ArrayList<Transaction>();
            transactionsOfThisAsset.add(transaction);
            transactionsByAsset.put(asset, transactionsOfThisAsset);

        }
        
        if (cmCache.containsKey(asset)) {
            Map<Bank, ECPoint> oldCache = cmCache.get(asset);
            Map<Bank, ECPoint> oldTokenCache = tokenCache.get(asset);
            for (Bank bank: this.participants) {
                ECPoint newValCache = oldCache.getOrDefault(bank, SECP256K1.CURVE.getInfinity()).add(transaction.getEntry(bank).getCM());
                oldCache.put(bank, newValCache);
                
                ECPoint newTokenCache = oldTokenCache.getOrDefault(bank, SECP256K1.CURVE.getInfinity()).add(transaction.getEntry(bank).getToken());
                oldTokenCache.put(bank, newTokenCache);
            } 
        }else {
            Map<Bank, ECPoint> newCache = new HashMap<Bank, ECPoint>();
            Map<Bank, ECPoint> newTokenCache = new HashMap<Bank, ECPoint>();
            for (Bank bank: this.participants) {
                newCache.put(bank, transaction.getEntry(bank).getCM());
                newTokenCache.put(bank, transaction.getEntry(bank).getToken());
            }
            
            cmCache.put(asset, newCache);
            tokenCache.put(asset, newTokenCache);
        }
        
        
        System.out.println("transfer completed");

    }  
   

    
    /**
     * Make a Deposit object that can be used to verify that the deposit respects invariants
     * @param asset the type of Asset this deposit takes place in
     * @param bank Bank involved in the deposit
     * @param amount the value of asset in the deposit, can be positive or negative
     * @param receiverTotalAsset the total amount of Asset asset held by bank upon the completion of the deposit
     * @param secretKey secret key held by this bank
     * @return a Deposit object containing all information needed to verify and/or append to the ledger
     */
    public synchronized DepositEntry makeDepositEntry(Asset asset, Bank bank, BigInteger amount, BigInteger receiverTotalAsset, BigInteger secretKey) {
        LocalDateTime time = LocalDateTime.now(clock);
        return new DepositEntry(this, asset, time, bank, amount, receiverTotalAsset, secretKey);
    }
    

    
    /**
     * Verify that a deposit respects all invariants and append it to the ledger. 
     * A deposit is ignored if it does not pass the verification
     * @param depositEntry the deposit to be verified
     */
    public synchronized void addDeposit(DepositEntry depositEntry) {
        Asset asset = depositEntry.getAsset();
        Bank bank = depositEntry.getBank();
        ECPoint cm = depositEntry.getCM();
        ECPoint token = depositEntry.getToken();
        
        if (depositEntry.verifyProof(this)) {
            if (cmCache.containsKey(asset)) {
                Map<Bank, ECPoint> oldCache = cmCache.get(asset);
                Map<Bank, ECPoint> oldTokenCache = tokenCache.get(asset);
                ECPoint newValCache = oldCache.getOrDefault(bank, SECP256K1.CURVE.getInfinity()).add(cm);
                oldCache.put(bank, newValCache);

                ECPoint newTokenCache = oldTokenCache.getOrDefault(bank, SECP256K1.CURVE.getInfinity()).add(token);
                oldTokenCache.put(bank, newTokenCache);
            } else {
                Map<Bank, ECPoint> newCache = new HashMap<Bank, ECPoint>();
                Map<Bank, ECPoint> newTokenCache = new HashMap<Bank, ECPoint>();

                newCache.put(bank, cm);
                newTokenCache.put(bank, token);

                cmCache.put(asset, newCache);
                tokenCache.put(asset, newTokenCache);

               

            }
            
            deposits.add(depositEntry);
            if (depositsByAsset.containsKey(asset)) { 
                depositsByAsset.get(asset).add(depositEntry);
           
            }else { 
                List<DepositEntry> depositsOfThisAsset = new ArrayList<DepositEntry>();
                depositsOfThisAsset.add(depositEntry);
                depositsByAsset.put(asset, depositsOfThisAsset);

            }
            System.out.println("deposit completed");
        }
        
        else {
            System.out.println("Proof Error, Deposit Ignored");
            
        }
    }
    
    /**
     * 
     * @param asset the Asset for which the auditing is conducted
     * @param bank the Bank being audited 
     * @param secretKey secret key of this bank
     * @param totalAsset the total amount of Asset asset held this bank claims to hold at the time of auditing 
     * @return a Sigma Protocol proving that the totalAsset input is consistent with the total asset recorded on the ledger
     */
    public SigmaProtocol makeAuditingProof(Asset asset, Bank bank, BigInteger secretKey, BigInteger totalAsset) {
        ECPoint sPrime = this.getCachedCM(asset, bank).subtract(GENERATOR_G.multiply(totalAsset));
        ECPoint t = this.getCachedToken(asset, bank);
        Function<BigInteger[], ECPoint[]> multiPower = (input) -> new ECPoint[] {sPrime.multiply(input[0]), GENERATOR_H.multiply(input[0])};
        return new SigmaProtocol(multiPower, new BigInteger[] {secretKey}, 
                                new BigInteger[] {SECP256K1.getRandomBigInt()}, new ECPoint[] {sPrime, GENERATOR_H});
    }
    
    /**
     * 
     * @param asset the Asset for which the auditing is conducted
     * @param bank the Bank being audited 
     * @param totalAsset the total amount of Asset asset this bank claims to hold at the time of auditing 
     * @param auditingProof a Sigma Protocol
     * @return true if and only if the total asset input is consistent with the total asset recorded on the ledger
     */
    public boolean verifyAuditing(Asset asset, Bank bank, BigInteger totalAsset, SigmaProtocol auditingProof) {
        ECPoint sPrime = this.getCachedCM(asset, bank).subtract(GENERATOR_G.multiply(totalAsset));
        ECPoint t = this.getCachedToken(asset, bank);
        Function<BigInteger[], ECPoint[]> multiPower = (input) -> new ECPoint[] {sPrime.multiply(input[0]), GENERATOR_H.multiply(input[0])};
        return auditingProof.verifyProof(multiPower, new ECPoint[] {t, bank.getPublicKey()},new ECPoint[] {sPrime, GENERATOR_H});
        
    }
    
    
    /**
     * 
     * @param asset the Asset that the commitment cache corresponds to 
     * @param bank the Bank that commitment cache corresponds to
     * @return sum of all commitments in Asset asset for Bank bank
     */
    public ECPoint getCachedCM(Asset asset, Bank bank) {
        return cmCache.getOrDefault(asset, new HashMap<Bank, ECPoint>()).getOrDefault(bank, SECP256K1.CURVE.getInfinity());
    }
    
    /**
     * 
     * @param asset the Asset that the token cache corresponds to 
     * @param bank the Bank that the token cache corresponds to
     * @return sum of all tokens in Asset asset for Bank bank
     */
    public ECPoint getCachedToken(Asset asset, Bank bank) {
        return tokenCache.getOrDefault(asset, new HashMap<Bank, ECPoint>()).getOrDefault(bank, SECP256K1.CURVE.getInfinity());
    }
    
    /**
     * Add new participants
     * @param banks Banks that will participate in later activities
     */
    public synchronized void addParticipant(List<Bank> banks) {
        for (Bank bank: banks) {
            this.participants.add(bank);
        }
    }
    
    /**
     * remove participants that will no longer involve in the financial activities if they are currently involved in activites
     * @param banks Banks to be removed
     */
    public synchronized void removeParticipant(List<Bank> banks) {
        for (Bank bank: banks) {
            if (this.participants.contains(bank)) {
                this.participants.remove(bank);
            }
        }
    }
}
