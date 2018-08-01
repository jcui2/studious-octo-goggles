package zkLedger;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.math.ec.ECPoint;

public class Main {
    public static void main(String[] args) {
       List<Bank> participants = new ArrayList<>();

       //DRY!!
        BigInteger boaSk = SECP256K1.getRandomBigInt();
        Bank boa = new Bank(boaSk);
       participants.add(boa);
       
       
       BigInteger jpMorganSk = SECP256K1.getRandomBigInt();
       Bank jpMorgan = new Bank(jpMorganSk);
       participants.add(jpMorgan);
   
       
       BigInteger goldmanSachsSk = SECP256K1.getRandomBigInt();
       Bank goldmanSachs = new Bank(goldmanSachsSk);
       participants.add(goldmanSachs);
       
       BigInteger citiSk = SECP256K1.getRandomBigInt();
       Bank citi = new Bank(citiSk);
       participants.add(citi);

       
       BigInteger chaseSk = SECP256K1.getRandomBigInt();
       Bank chase = new Bank(chaseSk);
       participants.add(chase);
        
       Ledger zkLedger = new Ledger(participants);
       
       zkLedger.transfer(Asset.CNY, boa, chase, new BigInteger("2000"), new BigInteger("-2000"), boaSk);
       System.out.println("transfer completed");
              
       zkLedger.transfer(Asset.CNY, chase, citi, new BigInteger("100"), new BigInteger("1900"), chaseSk);
       System.out.println("transfer2 completed");
       
       zkLedger.transfer(Asset.CNY, citi, boa, new BigInteger("50"), new BigInteger("50"), citiSk);
       System.out.println("transfer2 completed");
       
//       System.out.println(boa);
//       System.out.println(citi);
//       System.out.println(chase);
       
    }
        
}
