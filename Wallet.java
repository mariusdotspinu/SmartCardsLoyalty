/** 
 * Copyright (c) 1998, 2015, Oracle and/or its affiliates. All rights reserved.
 * 
 */

/*
 */

/*
 * @(#)Wallet.java	1.11 06/01/03
 */

package com.sun.jcclassic.samples.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class Wallet extends Applet {

	final static byte Loyalty_CLA = (byte) 0x80;
	
    final static byte VERIFY = (byte) 0x20;
    final static byte CREDIT = (byte) 0x30;
    final static byte DEBIT = (byte) 0x40;
    final static byte GET_BALANCE = (byte) 0x50;
    final static byte GET_BALANCE_POINTS = (byte) 0x65;
    
    final static byte P2_POINTS = (byte) 0x45;
    final static byte P1_MONEY = (byte) 0x55;
    
    final static byte NONE = (byte) 0x00;
    
    final static short MAX_BALANCE = 0x2710;
    final static short MAX_TRANSACTION_AMOUNT = 0x3E8;
	
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    final static byte MAX_PIN_SIZE = (byte) 0x08;
    
    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    // signal invalid transaction amount
    // amount > MAX_TRANSACTION_AMOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    
    // signal the the balance becomes negative
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    
    //signal not enough points
    final static short SW_NOT_ENOUGH_POINTS = 0x6A82;

    /* instance variables declaration */
    OwnerPIN pin;
    short balance = 0, points = 0;

    private Wallet(byte[] bArray, short bOffset, byte bLength) {

        // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        // The installation parameters contain the PIN
        // initialization value
        pin.update(bArray, (short) (bOffset + 1), aLen);
        register();

    } // end of the constructor

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a Wallet applet instance
        new Wallet(bArray, bOffset, bLength);
    } // end of install method

    @Override
    public boolean select() {

        // The applet declines to be selected
        // if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }

        return true;

    }// end of select method

    @Override
    public void deselect() {

        // reset the pin value
        pin.reset();

    }

    @Override
    public void process(APDU apdu) {

        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD

        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer

        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // verify the reset of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != Loyalty_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE:
                getBalance(apdu);
                return;
            case GET_BALANCE_POINTS:
            	getBalancePoints(apdu);
            	return;
            case DEBIT:
                debit(apdu);
                return;
            case CREDIT:
                credit(apdu);
                return;
            case VERIFY:
                verify(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    } // end of process method

    private void credit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        // Lc byte denotes the number of bytes in the
        // data field of the command APDU
        byte numBytes = buffer[ISO7816.OFFSET_LC];

        // indicate that this APDU has incoming data
        // and receive data starting from the offset
        // ISO7816.OFFSET_CDATA following the 5 header
        // bytes.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // it is an error if the number of data bytes
        // read does not match the number in Lc byte
        if ((numBytes != 2) || (byteRead != 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // get the credit amount
        byte creditAmountF = buffer[ISO7816.OFFSET_CDATA];
        byte creditAmountS = buffer[ISO7816.OFFSET_CDATA + 1];
        
        short creditAmount = 0;
        
        creditAmount = (short)( (creditAmountF<<8) | (creditAmountS & 0xFF) );

        // check the credit amount
        if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        if ((short) (balance + creditAmount) > MAX_BALANCE) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
        }

        // credit the amount
        balance = (short) (balance + creditAmount);

    }

    private void debit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        byte numBytes = (buffer[ISO7816.OFFSET_LC]);
        
        byte pointsAmountF, pointsAmountS, debitAmountF, debitAmountS;
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        
        
        byte p1_money = (buffer[ISO7816.OFFSET_P1]);
        byte p2_points = (buffer[ISO7816.OFFSET_P2]);
        
        if(p1_money == P1_MONEY && p2_points == NONE){ //we want to pay using only money
	
	        if ((numBytes != 2) || (byteRead != 2)) {
	            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        }

	        debitAmountF = buffer[ISO7816.OFFSET_CDATA];
	        debitAmountS = buffer[ISO7816.OFFSET_CDATA + 1];
	 
	        short debitAmount = 0;
	        debitAmount = (short)( (debitAmountF<<8) | (debitAmountS & 0xFF) );
	        
	        // check money amount
	        if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
	            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
	        }
	
	        //new balance
	        if ((short) (balance - debitAmount) < (short) 0) {
	            ISOException.throwIt(SW_NEGATIVE_BALANCE);
	        }
	
	        balance = (short) (balance - debitAmount);
	        points += (short) (debitAmount / 10);
        }
        
        else if (p1_money == NONE && p2_points == P2_POINTS){ //we want to pay using only points
        	
        	
	        if ((numBytes != 2) || (byteRead != 2)) {
	            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        }
	

	        pointsAmountF = buffer[ISO7816.OFFSET_CDATA];
	        pointsAmountS = buffer[ISO7816.OFFSET_CDATA + 1];
	        
	        short pointsAmount = 0;
	        pointsAmount = (short)( (pointsAmountF<<8) | (pointsAmountS & 0xFF) );
	        
	        // check points amount
	        if (pointsAmount < 0) {
	            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
	        }
	
	        //new points
	        if ((short) (points - pointsAmount) < (short) 0) {
	            ISOException.throwIt(SW_NOT_ENOUGH_POINTS);
	        }
	
	        points = (short) (points - pointsAmount);
	        
        }
        
        else if(p1_money == P1_MONEY && p2_points == P2_POINTS){ //combination

	        if ((numBytes != 4) || (byteRead != 4)) {
	            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        }
	        
	        debitAmountF = buffer[ISO7816.OFFSET_CDATA];
	        debitAmountS = buffer[ISO7816.OFFSET_CDATA + 1];
	        
	        pointsAmountF = buffer[ISO7816.OFFSET_CDATA + 2];
	        pointsAmountS = buffer[ISO7816.OFFSET_CDATA + 3];

	        
	        short debitAmount = 0, pointsAmount = 0;
	        
	        debitAmount = (short)( (debitAmountF<<8) | (debitAmountS & 0xFF) );
	        pointsAmount = (short)( (pointsAmountF<<8) | (pointsAmountS & 0xFF) );
	        
	        // check money amount
	        if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
	            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
	        }
	        
	        //new balance
	        if ((short) (balance - debitAmount) < (short) 0) {
	            ISOException.throwIt(SW_NEGATIVE_BALANCE);
	        }
	
	        balance = (short) (balance - debitAmount);
	       
	        //check points amount
	        if (pointsAmount < 0) {
	            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
	        }
	
	        //new points
	        if ((short) (points - pointsAmount) < (short) 0) {
	            ISOException.throwIt(SW_NOT_ENOUGH_POINTS);
	        }
	
	        points = (short) (points - pointsAmount);
	        points += (short) (debitAmount /10);
	        
	        
        }
        
        else{
        	ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
    }

    
    private void getBalance(APDU apdu) {
    	
    	if (!pin.isValidated()){
    		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    	}

        byte[] buffer = apdu.getBuffer();

        // inform system that the applet has finished
        // processing the command and the system should
        // now prepare to construct a response APDU
        // which contains data field
        short le = apdu.setOutgoing();

        if (le < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // informs the CAD the actual number of bytes
        // returned
        apdu.setOutgoingLength((byte) 2);

        // move the balance data into the APDU buffer
        // starting at the offset 0
        buffer[0] = (byte) (balance >> 8);
        buffer[1] = (byte) (balance & 0xFF);

        // send the 2-byte balance at the offset
        // 0 in the apdu buffer
        apdu.sendBytes((short) 0, (short) 2);

    } // end of getBalance method
    
    
    //get points
    private void getBalancePoints(APDU apdu){
    	if (!pin.isValidated()){
    		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    	}
    	
    	byte[] buffer = apdu.getBuffer();
    	short le = apdu.setOutgoing();
    	

        if (le < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        apdu.setOutgoingLength((byte) 2);
        
        buffer[0] = (byte) (points >> 8);
        buffer[1] = (byte) (points & 0xFF);

        apdu.sendBytes((short) 0, (short) 2);
    }

    private void verify(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }

    } // end of validate method
} // end of class Wallet

