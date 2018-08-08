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

       //NOT DRY :/
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
       
       DepositEntry depositOne = zkLedger.makeDepositEntry(Asset.CNY, boa, new BigInteger("1000"), new BigInteger("1000"), boaSk);
       zkLedger.addDeposit(depositOne);
       
       
       Transaction transferOne = zkLedger.makeTransaction(Asset.CNY, boa, chase, new BigInteger("10000"), new BigInteger("0"), boaSk);
       zkLedger.addTransaction(transferOne);
       
       
       SigmaProtocol auditingProof = zkLedger.makeAuditingProof(Asset.CNY, boa, boaSk, new BigInteger("1000"));
       System.out.println(zkLedger.verifyAuditing(Asset.CNY, boa, new BigInteger ("1000"), auditingProof));
       
              
       Transaction transferTwo =zkLedger.makeTransaction(Asset.CNY, boa, chase, new BigInteger("1000"), new BigInteger("0"), boaSk);
       zkLedger.addTransaction(transferTwo);
       
       Transaction transferThree = zkLedger.makeTransaction(Asset.CNY, chase, citi, new BigInteger("100"), new BigInteger("900"), chaseSk);
       zkLedger.addTransaction(transferThree);
       
       Transaction transferFour = zkLedger.makeTransaction(Asset.CNY, citi, boa, new BigInteger("50"), new BigInteger("50"), citiSk);
       zkLedger.addTransaction(transferFour);
       
       DepositEntry depositTwo = zkLedger.makeDepositEntry(Asset.CNY, citi, new BigInteger("250"), new BigInteger("300"), citiSk);
       zkLedger.addDeposit(depositTwo);
       
       Transaction transferFive = zkLedger.makeTransaction(Asset.CNY, citi, boa, new BigInteger("50"), new BigInteger("250"), citiSk);
       zkLedger.addTransaction(transferFive);
       
    }
        
}
