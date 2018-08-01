package zkLedger;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.math.ec.ECPoint;

public class Ledger{
   //generators used in the zkLedger
   public static final ECPoint GENERATOR_G = SECP256K1.pointDecompressFromString(
                                             SECP256K1.SHA256.digest("0".getBytes(StandardCharsets.UTF_8)));
   public static final ECPoint GENERATOR_H = SECP256K1.pointDecompressFromString(
                                             SECP256K1.SHA256.digest("1".getBytes(StandardCharsets.UTF_8)));
    
    private final List<Bank> participants; //list of banks currently participating in transactions
    private final List<Transaction> transactions; //list of transaction record ordered by time --> synchronized!!!
    private final Map<Asset, List<Transaction>> transactionsByAsset; //a map from type of asset to transactions of that asset
    private final Map<Asset, Map<Bank, ECPoint>> cmCache;
    private final Map<Asset, Map<Bank, ECPoint>> tokenCache;
    private final Clock clock;
    
    
    /**
     * Construct a new ledgers with participants currently involved in transactions, transctions initiated 
     * to be an empty list and transactionsByAsset an empty map.
     * @param participants banks currently participating in transactions
     */
    public Ledger(List<Bank> participants) {
        this.participants = participants;
        this.transactions = new ArrayList<Transaction>();
        this.transactionsByAsset = new HashMap<Asset, List<Transaction>>();
        this.clock = Clock.systemDefaultZone();
        this.cmCache = new HashMap<Asset, Map<Bank, ECPoint>>();
        this.tokenCache = new HashMap<Asset, Map<Bank, ECPoint>>();
    }
    
    /**
     * Create and verify a transaction 
     * @param asset the asset of transaction
     * @param time time of transaction
     * @param senderBank bank that sends money
     * @param receiverBank bank that receives money
     * @param amount the amount of money in this transaction positive
     */
    public synchronized void transfer(Asset asset, Bank senderBank, Bank receiverBank, BigInteger amount, BigInteger senderTotalAsset, BigInteger secretKey) {
        LocalDateTime time = LocalDateTime.now(clock);
        Transaction transaction = new Transaction(this, asset, time, senderBank, receiverBank, 
                                                  amount, senderTotalAsset,
                                                  new ArrayList<Bank>(this.participants), secretKey);
        //verify this transaction
        // multithreaded?
        
//        List<Thread> listOfThread = new ArrayList<>();
//        List<Boolean> allResult = new ArrayList<>();
//        for (Bank bank: participants) {
//            Thread thread = new Thread(new Runnable() {
//                public void run() {
//                    boolean result = transaction.verify();
//                    synchronized(allResult) {
//                        allResult.add(result);
//                    }
//                }
//            });
//            
//            listOfThread.add(thread);
//        }
//        
//        for(Thread thread: listOfThread) {
//            thread.start();
//        }
//        
//        for(Thread thread: listOfThread) {
//            try {
//            thread.join();
//            } catch(Exception e) {
//                e.printStackTrace();
//            }
//        }
//        
//        for (boolean result: allResult) {
//            if (result == false) {
//                System.out.println("Proof Error");
//                return;
//            }
//        }
        
         if (!transaction.verify()) {
             System.out.println("Proof Error");
             return;
         }
        
        System.out.println("proof verified, adding transaction to ledger"); 
         
        transactions.add(transaction);
        if (transactionsByAsset.containsKey(asset)) { //update cache
            transactionsByAsset.get(asset).add(transaction);
            Map<Bank, ECPoint> oldCache = cmCache.get(asset);
            Map<Bank, ECPoint> oldTokenCache = tokenCache.get(asset);
            for (Bank bank: this.participants) {
                ECPoint newValCache = oldCache.getOrDefault(bank, SECP256K1.CURVE.getInfinity()).add(transaction.getEntry(bank).getCM());
                oldCache.put(bank, newValCache);
                
                ECPoint newTokenCache = oldTokenCache.getOrDefault(bank, SECP256K1.CURVE.getInfinity()).add(transaction.getEntry(bank).getToken());
                oldTokenCache.put(bank, newTokenCache);
            } 
            
        }else { //assume consistent
            List<Transaction> transactionsOfThisAsset = new ArrayList<Transaction>();
            transactionsOfThisAsset.add(transaction);
            Map<Bank, ECPoint> newCache = new HashMap<Bank, ECPoint>();
            Map<Bank, ECPoint> newTokenCache = new HashMap<Bank, ECPoint>();
            for (Bank bank: this.participants) {
                newCache.put(bank, transaction.getEntry(bank).getCM());
                newTokenCache.put(bank, transaction.getEntry(bank).getToken());
            }
            transactionsByAsset.put(asset, transactionsOfThisAsset);
            cmCache.put(asset, newCache);
            tokenCache.put(asset, newTokenCache);


            
        }
        
        System.out.println("transfer completed");
        

    }  
   
    //Listener gets called everything a new transfer happened?
    
//    public List<Bank> getBanks(){
//        return new ArrayList<Bank>(this.participants);
//    }
//    
    public ECPoint getCachedCM(Asset asset, Bank bank) {
        return cmCache.getOrDefault(asset, new HashMap<Bank, ECPoint>()).getOrDefault(bank, SECP256K1.CURVE.getInfinity());
    }
    
    public ECPoint getCachedToken(Asset asset, Bank bank) {
//        if (!tokenCache.containsKey(asset) ||! tokenCache.get(asset).containsKey(bank)) {
//            System.out.println("asset not in here");
//            return SECP256K1.CURVE.getInfinity();
//            
//        }
//        else {
//            return tokenCache.get(asset).get(bank);
//        }
        return tokenCache.getOrDefault(asset, new HashMap<Bank, ECPoint>()).getOrDefault(bank, SECP256K1.CURVE.getInfinity());
    }
}
