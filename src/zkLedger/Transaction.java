package zkLedger;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.bouncycastle.math.ec.ECPoint;

public class Transaction {
    private Asset asset;
    private LocalDateTime time;
    private Map<Bank, Entry> record;
    
    /**
     * Create a transaction record of bank senderBank send amount many shares of asset asset to receiverBank
     * @param asset the asset of transaction
     * @param time time of transaction
     * @param senderBank bank that sends money
     * @param receiverBank bank that receives money
     * @param amount the amount of money in this transaction
     */
    public Transaction(Ledger ledger, Asset asset, LocalDateTime time, Bank senderBank, Bank receiverBank, 
                        BigInteger amount, BigInteger senderTotalAsset,
                        List<Bank> participants, BigInteger secretKey) {
        this.asset = asset;
        this.time = time;
        this.record = Collections.synchronizedMap(new HashMap<Bank, Entry>());
        List<Thread> allthread = new ArrayList<Thread>();
        
        
        BigInteger rSoFar = BigInteger.ZERO;
        BigInteger rPrimeSoFar = BigInteger.ZERO;
        for (int i=0; i < participants.size(); i++) {
            BigInteger r;
            BigInteger rPrime;
            if (i != participants.size()-1) { //need to account for the case when all first n-1 numbers sum to 0 mod p
                r = SECP256K1.getRandomBigInt();
                rPrime = SECP256K1.getRandomBigInt();
                rSoFar = rSoFar.add(r);
                rPrimeSoFar = rPrimeSoFar.add(rPrime);
            }
            else {
                r = SECP256K1.P.subtract(rSoFar).mod(SECP256K1.P);
                rPrime = SECP256K1.P.subtract(rPrimeSoFar).mod(SECP256K1.P);
                
            }
            
            final int currentIndex = i;
            final BigInteger randomness = r;
            final BigInteger randomnessPrime = rPrime;
            
            Thread thread  = new Thread(new Runnable() {
                public void run() {
                    BigInteger amountReceived;
                    BigInteger recommitValue;
                    BigInteger[] poaSecretMessage;
                    if (participants.get(currentIndex).equals(senderBank)) {
                        amountReceived = amount.negate();
                        recommitValue = senderTotalAsset;
                        poaSecretMessage = new BigInteger[] {secretKey};
                    }else if(participants.get(currentIndex).equals(receiverBank)) {
                        amountReceived = amount;
                        recommitValue = amount;
                        poaSecretMessage = new BigInteger[] {amount, r, rPrime};
                    }else {
                        amountReceived = BigInteger.ZERO;
                        recommitValue = BigInteger.ZERO;
                        poaSecretMessage = new BigInteger[] {BigInteger.ZERO, r, rPrime};
                    }

                    // create entry for current bank
                    Entry entry = new Entry(ledger, asset, participants.get(currentIndex), 
                                            amountReceived, randomness,
                                            recommitValue, randomnessPrime, poaSecretMessage);
                    record.put(participants.get(currentIndex), entry);

                }
            });
            thread.start();
            allthread.add(thread);
            
        }
        

        try {
            for (Thread thread: allthread) {
                thread.join();
            }
        }catch (InterruptedException e) {
            e.printStackTrace();
        }
        
        
    }
    
    
    //verify that the sum of randomness is zero
    /**
     * @return true if and only if all entries are consistent, have enough asset, and the entire transaction 
     *         have overall balance 0.
     */
    public boolean verify() {
        List<Boolean> allResult = new ArrayList<>();
        List<Thread> oneThreadPerEntry = new ArrayList<>();
        ECPoint totalCM = SECP256K1.CURVE.getInfinity();

        for (Bank bank: record.keySet()) {
            Thread thread = new Thread(
                new Runnable() {
                    public void run(){
                        boolean result = record.get(bank).verify();
                        synchronized(allResult) {
                            allResult.add(result);
                        }
                        }
                    });
            oneThreadPerEntry.add(thread);
            
            
            totalCM = totalCM.add(record.get(bank).getCM());
        }
        
        if (!totalCM.equals(SECP256K1.CURVE.getInfinity())) {
            System.out.println("proof of balance not obeyed");
            return false;
        }
        
        System.out.println("poof of balance checked");
        
        for (Thread thread: oneThreadPerEntry) {
            thread.start();
        }
        
        for (Thread thread: oneThreadPerEntry) {
            try {
                thread.join();
            }catch(Exception e) {
                e.printStackTrace();
            }
        }
        
        for(boolean result: allResult) {
            if (result == false) {
                return false;
            }
        }
        
        
        
        
        return true;
    }
    
    public Asset getAsset() {
        return this.asset;
    }
    
    public Entry getEntry(Bank bank) {
        return record.get(bank);
    }
}
