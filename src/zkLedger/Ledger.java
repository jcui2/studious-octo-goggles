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

public class Ledger{
   //generators used in the zkLedger
   public static final ECPoint GENERATOR_G = SECP256K1.makeGeneratorFromString("0");
   public static final ECPoint GENERATOR_H = SECP256K1.makeGeneratorFromString("1");
   
   public static final Function<BigInteger[], ECPoint> PEDERSON = (input) 
                                                                     -> (GENERATOR_G.multiply(input[0])).add(GENERATOR_H.multiply(input[1]));
    
    private final List<Bank> participants; //list of banks currently participating in transactions
    private final List<Transaction> transactions; //list of transaction record ordered by time
    private final Map<Asset, List<Transaction>> transactionsByAsset; //a map from type of asset to transactions of that asset
    private final List<DepositEntry> deposits; //list of deposits record ordered by time
    private final Map<Asset, List<DepositEntry>> depositsByAsset;//a map from type of asset to deposits of that asset
    private final Map<Asset, Map<Bank, ECPoint>> cmCache; 
    private final Map<Asset, Map<Bank, ECPoint>> tokenCache;
    private final Clock clock;
    
    
    /**
     * Construct a new ledger with banks participants currently involved in transactions
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
     * 
     * @param asset
     * @param senderBank
     * @param receiverBank
     * @param amount
     * @param senderTotalAsset
     * @param secretKey
     * @return
     */
    public synchronized Transaction makeTransaction(Asset asset, Bank senderBank, Bank receiverBank, BigInteger amount,
                                                    BigInteger senderTotalAsset, BigInteger secretKey) {
        LocalDateTime time = LocalDateTime.now(clock);
        Transaction transaction = new Transaction(this, asset, time, senderBank, receiverBank, 
                                                  amount, senderTotalAsset,
                                                  new ArrayList<Bank>(this.participants), secretKey);
        return transaction;
    }
    
//    /**
//     * Create and verify a transaction 
//     * @param asset the asset of transaction
//     * @param time time of transaction
//     * @param senderBank bank that sends money
//     * @param receiverBank bank that receives money
//     * @param amount the amount of money in this transaction positive
//     */
    /**
     * 
     * @param asset
     * @param transaction
     */
    public synchronized void addTransaction(Asset asset, Transaction transaction) {
         if (!transaction.verify(this)) {
             System.out.println("Proof Error, transacation ignored");
             return;
         }
        
        System.out.println("proof verified, adding transaction to ledger"); 
         
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
   

    public ECPoint getCachedCM(Asset asset, Bank bank) {
        return cmCache.getOrDefault(asset, new HashMap<Bank, ECPoint>()).getOrDefault(bank, SECP256K1.CURVE.getInfinity());
    }
    
    public ECPoint getCachedToken(Asset asset, Bank bank) {
        return tokenCache.getOrDefault(asset, new HashMap<Bank, ECPoint>()).getOrDefault(bank, SECP256K1.CURVE.getInfinity());
    }
    
    
    public synchronized DepositEntry makeDepositEntry(Asset asset, Bank bank, BigInteger amount, BigInteger receiverTotalAsset, BigInteger secretKey) {
        LocalDateTime time = LocalDateTime.now(clock);
        return new DepositEntry(this, asset, time, bank, amount, receiverTotalAsset, secretKey);
    }
    
    
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

                System.out.println("deposit completed");

            }
            
            deposits.add(depositEntry);
            if (depositsByAsset.containsKey(asset)) { 
                depositsByAsset.get(asset).add(depositEntry);
           
            }else { 
                List<DepositEntry> depositsOfThisAsset = new ArrayList<DepositEntry>();
                depositsOfThisAsset.add(depositEntry);
                depositsByAsset.put(asset, depositsOfThisAsset);

            }
            
        }
        
        else {
            System.out.println("Proof Error, Deposit Ignored");
            
        }
    }
    
    
    public SigmaProtocol makeAuditingProof(Asset asset, Bank bank, BigInteger secretKey, BigInteger totalAsset) {
        ECPoint sPrime = this.getCachedCM(asset, bank).subtract(GENERATOR_G.multiply(totalAsset));
        ECPoint t = this.getCachedToken(asset, bank);
        Function<BigInteger[], ECPoint[]> multiPower = (input) -> new ECPoint[] {sPrime.multiply(input[0]), GENERATOR_H.multiply(input[0])};
        return new SigmaProtocol(multiPower, new BigInteger[] {secretKey}, 
                                new BigInteger[] {SECP256K1.getRandomBigInt()}, new ECPoint[] {sPrime, GENERATOR_H});
    }
    
    public boolean verifyAuditing(Asset asset, Bank bank, BigInteger totalAsset, SigmaProtocol auditingProof) {
        ECPoint sPrime = this.getCachedCM(asset, bank).subtract(GENERATOR_G.multiply(totalAsset));
        ECPoint t = this.getCachedToken(asset, bank);
        Function<BigInteger[], ECPoint[]> multiPower = (input) -> new ECPoint[] {sPrime.multiply(input[0]), GENERATOR_H.multiply(input[0])};
        return auditingProof.verifyProof(multiPower, new ECPoint[] {t, bank.getPublicKey()},new ECPoint[] {sPrime, GENERATOR_H});
        
    }
    
    
    
    
    
}
