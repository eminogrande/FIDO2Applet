/*
 * ------------------------------------------------------------------------------------------------------------------ *
 *                                                                                                                    *
 * Copyright (c) 2023 IDEX Biometrics ASA. All Rights Reserved.   
 * 
 * DISCLAIMER OF WARRANTY/LIMITATION OF REMEDIES: unless otherwise agreed, IDEX
 * Biometrics ASA has no obligation to support this software, and the software 
 * is provided "AS IS", with no express or implied warranties of any kind, and
 * IDEX Biometrics ASA is not to be liable for any damages, any relief, or for
 * any claim by any third party, arising from use of this software.                                                       *
 *                                                                                                                    *                                                                                                                 *
 * ------------------------------------------------------------------------------------------------------------------ *
 */
//--------------------------------------------------------------------------------------------------------------------
// Package Definition
//--------------------------------------------------------------------------------------------------------------------

package com.idex.client;

//--------------------------------------------------------------------------------------------------------------------
// Library Imports
//--------------------------------------------------------------------------------------------------------------------

//javacard API
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;

//GP API
import org.globalplatform.GPSystem;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.SecureChannel;

//IBA Shareable Interface
import com.idex.iba.service.enrollInterface;
import com.idex.iba.service.verifyInterface;

// --------------------------------------------------------------------------------------------------------------------
// Class Definition
//--------------------------------------------------------------------------------------------------------------------
/**
 * client Applet Class
 */
public  class client extends Applet
{
	private final static byte CLA_GP = (byte)0x80;
	
    // 'INS' Bytes
    private interface INS
    {
         //GP Secure Channel
         static final byte B_INIT_UPDATE = (byte)0x50;
         static final byte B_EXT_AUTH = (byte)0x82;   
         static final byte B_IBA_ACCESS = (byte)0x59;
         
    }
    
    // IBA 'P1' Bytes
    interface P1
    {

	     final static byte B_VERIFYENROLL= (byte)0x00;
	   	 final static byte B_SINGLEENROLL= (byte)0x03;
	   	 final static byte B_GETENSTATUS= (byte)0x04;
	   	 final static byte B_GETCURRENT= (byte)0x01;	   	 
	   	 final static byte B_DELTEMP= (byte)0x08;
	   	 final static byte B_CHECKVERIFY= (byte)0x07;
	   	 final static byte B_VERIFY= (byte)0x06;
	   	 final static byte B_DELETEFINGER= (byte)0x02;
	   	 
    }
    
	 
    // Applet Registry
    private GPRegistryEntry gpRegEntry;
    // GP Secure Channel
    private SecureChannel gpSecChan;
    
	// IBA Applet AID bytes
	private final byte[] ibaAIDBytes = {(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x09,(byte)0x05,
    				(byte)0x01,(byte)0x00,(byte)0x01,(byte)0x01};
	
	private AID ibaAID;

    // ----------------------------------------------------------------------------------------------------------------
    // Pubic Method Install Applet
    // ----------------------------------------------------------------------------------------------------------------
    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        // GP-Compliant JavaCard Applet Registration   	
    	// Multi-instances support
		new client().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }
     
    // ----------------------------------------------------------------------------------------------------------------
    // Public Methods Applet
    // ----------------------------------------------------------------------------------------------------------------

	public void process(APDU apdu)
    {
        // Select Applet
		if (selectingApplet()) 
		{
           if (gpRegEntry == null)
           {
               gpRegEntry = GPSystem.getRegistryEntry(null);
           }
           if (gpSecChan == null)
           {
               gpSecChan = GPSystem.getSecureChannel();
           }   
           return;
		} 
       
        byte[] apduBuf = apdu.getBuffer();
        short sRspLen = 0;
        Shareable SIO = null;
     
        if((apduBuf[ISO7816.OFFSET_CLA]&(byte)0xF0)!=CLA_GP 
        		&&apduBuf[ISO7816.OFFSET_CLA]!= ISO7816.CLA_ISO7816 )
        	 ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		// Receive Command Data
		if (apduBuf[ISO7816.OFFSET_LC] != 0) 
		{
			apdu.setIncomingAndReceive();
		}
         
  		if(apduBuf[ISO7816.OFFSET_INS] == INS.B_IBA_ACCESS)
  		{          
	  		ibaAID = JCSystem.lookupAID(ibaAIDBytes, (short)0x00,(byte)ibaAIDBytes.length);
	  		
	  	    if(ibaAID == null) 
	  	    {
	            // Cannot find the ibaAID
	            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
	        }

		  	if(apduBuf[ISO7816.OFFSET_P1] == P1.B_VERIFY || apduBuf[ISO7816.OFFSET_P1] == P1.B_GETCURRENT
		  			|| apduBuf[ISO7816.OFFSET_P1] == P1.B_CHECKVERIFY)
		  	{
			  	try
			  	{
			  		SIO = (verifyInterface)JCSystem.getAppletShareableInterfaceObject(ibaAID, (byte)0);
			  	}
			  	catch(SecurityException e)
			  	{
			  		ISOException.throwIt((short)0x9B11);
			  	}
			  	
		  	}
		  	else
		  	{		 
		  		try
			  	{
			  		SIO = (enrollInterface)JCSystem.getAppletShareableInterfaceObject(ibaAID, (byte)1);
			  	}
			  	catch(SecurityException e)
			  	{
			  		ISOException.throwIt((short)0x9B22);
			  	}
		  	}

	
	  		if(SIO == null)
	  			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
  		}
  		
        switch (apduBuf[ISO7816.OFFSET_INS])
         { 
        	// Process GP Secure Channel Commands
         	case INS.B_INIT_UPDATE:
         	case INS.B_EXT_AUTH:
		         {
		        	sRspLen = gpSecChan.processSecurity(apdu);
		            break;
		         }
		    // Process Biometrics Commands
         	case INS.B_IBA_ACCESS:

         		 switch (apduBuf[ISO7816.OFFSET_P1])
         		 {
         		        // Verify Interface
			            case P1.B_VERIFY:
			            	 sRspLen = ((verifyInterface) SIO).verify(apduBuf,(short)ISO7816.OFFSET_CDATA);
			            	 if(sRspLen ==(short)-1)
				             {   
			            		 ISOException.throwIt(Util.makeShort(apduBuf[ISO7816.OFFSET_CDATA], apduBuf[ISO7816.OFFSET_CDATA+1]));
			                 }  			            	 
			            	 break;  
			        		 
			       	    case P1.B_CHECKVERIFY:			       	    	
			            	 sRspLen = ((verifyInterface) SIO).checkVerifyResult(apduBuf,(short)ISO7816.OFFSET_CDATA);
			            	 if(sRspLen ==(short)-1)
				             {   
			            		 ISOException.throwIt(Util.makeShort(apduBuf[ISO7816.OFFSET_CDATA], apduBuf[ISO7816.OFFSET_CDATA+1]));
			                 }  
			           		 break;

			            case P1.B_GETCURRENT:
			            	 sRspLen = ((verifyInterface) SIO).getCurrent(apduBuf,(short)ISO7816.OFFSET_CDATA);
			            	 if(sRspLen ==(short)-1)
				             {   
			            		 ISOException.throwIt(Util.makeShort(apduBuf[ISO7816.OFFSET_CDATA], apduBuf[ISO7816.OFFSET_CDATA+1]));
			                 }             
			           	     break; 			           	     			            
			      		           
			           // Enroll Interface    
			            case P1.B_SINGLEENROLL:
			            	 byte Flag = apduBuf[ISO7816.OFFSET_CDATA];
			            	 byte FingerIndex = apduBuf[ISO7816.OFFSET_CDATA+1];
			            	 sRspLen =((enrollInterface) SIO).singleEnroll(FingerIndex, Flag, apduBuf, (short)ISO7816.OFFSET_CDATA);
			            	 if(sRspLen ==(short)-1)
				             {   
			            		 ISOException.throwIt(Util.makeShort(apduBuf[ISO7816.OFFSET_CDATA], apduBuf[ISO7816.OFFSET_CDATA+1]));
			                 }   
			            	 break; 
			        			            
			            case P1.B_VERIFYENROLL:   //Enroll qualification 	 
			            	 byte vFlag = apduBuf[ISO7816.OFFSET_CDATA];
			            	 
			            	 sRspLen = ((enrollInterface) SIO).verifyEnroll(vFlag, apduBuf, (short)ISO7816.OFFSET_CDATA);
			            	 
			            	 if(sRspLen ==(short)-1)
				             {   
			            		 ISOException.throwIt(Util.makeShort(apduBuf[ISO7816.OFFSET_CDATA], apduBuf[ISO7816.OFFSET_CDATA+1]));
			                 }   
			            	 break;   
			         	     
			            case P1.B_GETENSTATUS: 
			            	 if(apduBuf[ISO7816.OFFSET_P2] == (byte)0) // Global APDU buffer
			            	 {
				            	 sRspLen = ((enrollInterface) SIO).getEnrollStatus(apduBuf, (short)ISO7816.OFFSET_CDATA );
				            	 if(sRspLen ==(short)-1)
					             {   
				            		 ISOException.throwIt(Util.makeShort(apduBuf[ISO7816.OFFSET_CDATA], apduBuf[ISO7816.OFFSET_CDATA+1]));
				                 } 
			            	 }
			            	 else  // Local APDU buffer 
			            	 {
			     		         // baOutBuf must be Global Array,COR
			     		         // Set larger buffer >= 0x80
			     		  		 byte[] baOutBuf = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)0x80);
			     		        
			     		 	     // Schedule a clean-up of COR/COD objects, Mandatory
			                     JCSystem.requestObjectDeletion(); 
			                     
				            	 sRspLen = ((enrollInterface) SIO).getEnrollStatus(baOutBuf, (short) 0);
				            	 if(sRspLen ==(short)-1)
					             {   
				            		 ISOException.throwIt(Util.makeShort(baOutBuf[0], baOutBuf[1]));
				                 }
				            	 else
				            	 {
				            		 Util.arrayCopyNonAtomic(baOutBuf, (short)0, apduBuf, (short)ISO7816.OFFSET_CDATA, sRspLen);        	  
				            	 } 
			            	 }
			        	     break;        			           	 
			        		 
			            case P1.B_DELTEMP:
			              	 sRspLen = ((enrollInterface) SIO).deleteTemplates( apduBuf,(short)ISO7816.OFFSET_CDATA);
			              	 
			            	 if(sRspLen ==(short)-1)
				             {   
			            		 ISOException.throwIt(Util.makeShort(apduBuf[ISO7816.OFFSET_CDATA], apduBuf[ISO7816.OFFSET_CDATA+1]));
			                 }   		           	 	 
			            	 break;
			            
			            case P1.B_DELETEFINGER:		            	 
			              	 byte FingerID = apduBuf[ISO7816.OFFSET_CDATA];		              				              	
			              	 sRspLen = ((enrollInterface) SIO).deleteFinger(FingerID, apduBuf,(short)ISO7816.OFFSET_CDATA );
			              	 				            
			            	 if(sRspLen ==(short)-1)
				             {   
			            		 ISOException.throwIt(Util.makeShort(apduBuf[ISO7816.OFFSET_CDATA], apduBuf[ISO7816.OFFSET_CDATA+1]));
			                 } 
			            	 break;
			            	 
	                    // Invalid 'P1'
	                    default:
	                    {
	                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	                    }
         	     }
         	     break;
           // Invalid 'INS'	    
           default:
        	     ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        
        if(gpSecChan.getSecurityLevel()!=SecureChannel.NO_SECURITY_LEVEL)
        {
            Util.setShort(apduBuf, (short)(ISO7816.OFFSET_CDATA + sRspLen), ISO7816.SW_NO_ERROR);
            sRspLen = gpSecChan.wrap(apduBuf, ISO7816.OFFSET_CDATA, (short)(2 + sRspLen));
        } 

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, sRspLen); 
}
    public void deselect()
    {
        // Reset on Deselect if any
        gpSecChan.resetSecurity();
    }

}
