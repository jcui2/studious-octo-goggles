package zkLedger;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

import zkLedger.OrProof.OrProofIndex;

public class RangeProof {
    private OrProof[] orProofByBit;
    private ECPoint[] cmByBit;
    public static final Function<BigInteger[], ECPoint[]> EXPO = (input) -> new ECPoint[] {Ledger.GENERATOR_H.multiply(input[1])};
    
    
    public RangeProof(BigInteger recommitVal, BigInteger randomnessPrime) {
        this.orProofByBit = new OrProof[40];
        this.cmByBit = new ECPoint[40];
        String recommitValInBit = recommitVal.toString(2);
        
        List<Thread> oneThreadPerBit = new ArrayList<>();
        
        BigInteger rSoFar = BigInteger.ZERO;
        
        for (int i=0; i < 40; i++) {
            BigInteger r;
        
            if (i != 39) {
                r = SECP256K1.getRandomBigInt();
                rSoFar = rSoFar.add(r);
            } else {
                r = randomnessPrime.subtract(rSoFar).mod(SECP256K1.P);
            }
            
            int index = i;
            
            Thread thread = new Thread(new Runnable() {
                public void run() {        
                    OrProof currentBit;
                    ECPoint cm;
                    
                    if (index < 40 - recommitValInBit.length() ||
                        recommitValInBit.charAt(index-40+recommitValInBit.length()) != '1') {
                        
                        cm = Ledger.PEDERSON.apply(new BigInteger[] {BigInteger.ZERO, r});
                        
                        currentBit = new OrProof(OrProofIndex.FIRST,new BigInteger[] {BigInteger.ZERO, r}, 
                                                 EXPO, EXPO, new ECPoint[] {cm}, new ECPoint[] {cm.subtract(Ledger.GENERATOR_G.multiply(new BigInteger("2").pow(39-index)))},
                                                 new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H},
                                                 2, 8);
                    }else {
                        cm = Ledger.PEDERSON.apply(new BigInteger[] {new BigInteger("2").pow(39-index), r});
                        currentBit = new OrProof(OrProofIndex.SECOND, new BigInteger[] {new BigInteger("2").pow(39-index), r}, 
                                EXPO, EXPO,
                                new ECPoint[] {cm}, new ECPoint[] {cm.subtract(Ledger.GENERATOR_G.multiply(new BigInteger("2").pow(39-index)))},
                                new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H},
                                2, 8);
                    }
                    
                    synchronized(orProofByBit) {
                        orProofByBit[index] = currentBit;
                        cmByBit[index] = cm;
                    }
                    

                }
            });
            
            oneThreadPerBit.add(thread);

        }
        
        for (Thread thread : oneThreadPerBit) {
            thread.start();
        }
        
        try {
            for (Thread thread : oneThreadPerBit) {
                thread.join();
            }
        }catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    
    public boolean VerifyProof(ECPoint cmPrime) {
        ECPoint cmByBitSum = SECP256K1.CURVE.getInfinity();
        for (int i = 0; i < 40 ; i++) {
            cmByBitSum = cmByBitSum.add(this.cmByBit[i]);
        }
        
        if (! cmByBitSum.equals(cmPrime)) {
            System.out.println(cmPrime + "and " + cmByBitSum);
            return false;
        }
        
        List<Thread> oneThreadPerBit = new ArrayList<>();
        boolean[] perBitOrResult = new boolean[40];
        
        
        for (int i = 0; i < 40; i++) {
            int index = i;
            
            Thread thread = new Thread(new Runnable(){
                    public void run() {
                        boolean result = orProofByBit[index].verifyProof(EXPO, EXPO, 
                                new ECPoint[] {cmByBit[index]}, new ECPoint[] {cmByBit[index].subtract(Ledger.GENERATOR_G.multiply(new BigInteger("2").pow(39-index)))},
                                new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}, new ECPoint[] {Ledger.GENERATOR_G, Ledger.GENERATOR_H}, 8);
           
                        
                        synchronized(perBitOrResult) {
                            perBitOrResult[index] = result;
                        }
                    } 
            });
            
            oneThreadPerBit.add(thread);
        }
        
        for (Thread thread : oneThreadPerBit) {
            thread.start();
        }
        
        try {
            for (Thread thread : oneThreadPerBit) {
                thread.join();
            }
        }catch (Exception e) {
            e.printStackTrace();
        }
        
        for (boolean result: perBitOrResult) {
            if (! result) {
                return false;
            }
        }
        
        return true;
    }
    
    
}
