package net.tmcf.snmp;

import java.io.IOException;

import org.apache.log4j.Logger;
import org.snmp4j.CommunityTarget;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.transport.DefaultUdpTransportMapping;

/**
 * Sets up SNMP  and the community target.
 * 
 * @author tfuntani
 *
 */
public class SimpleSnmpWalker {

	private static final Logger LOG = Logger.getLogger(SnmpWalkerTask.class);

	private static SimpleSnmpWalker instance = null;

	private static final String targetAddr = System.getProperty("target.host") + "/161";

	private static TransportMapping transport;
	private static Target target;
	private static Snmp snmp;
	private static byte[] localEngineID;

	private SimpleSnmpWalker() {	
	}

	public static SimpleSnmpWalker getInstance() {
		if (instance == null) {
			instance = new SimpleSnmpWalker();
			init();
		}
		return instance;
	}

	private static void init() {

		LOG.debug("Setting up target... ");

		final String securityName = System.getProperty("security.name");
		Address targetAddress = GenericAddress.parse("udp:" + targetAddr);

		try {

			if (getSnmpVersion(System.getProperty("snmp.version")) == SnmpConstants.version3) {
				transport = new DefaultUdpTransportMapping();
				snmp = new Snmp(transport);

				localEngineID = MPv3.createLocalEngineID();
				USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(localEngineID), 0);
				SecurityModels.getInstance().addSecurityModel(usm);

				transport.listen();

				OID authProtocol = getAuthProtocol(System.getProperty("auth.protocol"));
				final String authPassphrase = System.getProperty("auth.key");
				OctetString ap = (authPassphrase == null) ? null : new OctetString(authPassphrase);

				OID privProtocol = getPrivProtocol(System.getProperty("priv.protocol"));
				final String privPassphrase = System.getProperty("priv.key");
				OctetString pp = (privPassphrase == null) ? null : new OctetString(privPassphrase);

				snmp.getUSM().addUser(new OctetString(securityName), new UsmUser(new OctetString(securityName), authProtocol, 
						ap, privProtocol, pp));

				// create the target
				target = new UserTarget();
				target.setSecurityLevel(getSecurityLevel(System.getProperty("security.level")));
				target.setSecurityName(new OctetString(securityName));
				target.setAddress(targetAddress);
				target.setRetries(2);
				target.setTimeout(60000);
				target.setVersion(SnmpConstants.version3);

				LOG.debug("snmpVersion: " + SnmpConstants.version3 + "; targetAddress: " + targetAddress + 
						"; securityLevel: " + System.getProperty("security.level"));					
			} else {
				
				transport = new DefaultUdpTransportMapping();
				snmp = new Snmp(transport);
				transport.listen();
				
				int snmpVersion = getSnmpVersion(System.getProperty("snmp.version"));
				target = new CommunityTarget(targetAddress, new OctetString(System.getProperty("community")));

				target.setRetries(2);
				target.setTimeout(60000);
				target.setVersion(snmpVersion);
				
				LOG.debug("snmpVersion: " + snmpVersion + "; targetAddress: " + targetAddress + "; communityString: " + System.getProperty("community"));	
			}
			
		} catch (IOException e) {
			LOG.error("Exception while setting up the transport mapping.", e);
		}

	}

	public Target getTarget() {
		return target;
	}

	public Snmp getSnmp() {
		return snmp;
	}

	private static int getSnmpVersion(String str) {	

		if (str.equals("v1")) {
			return SnmpConstants.version1;
		} else if (str.equals("v2c")) {
			return SnmpConstants.version2c;
		} else {
			return SnmpConstants.version3;
		}

	}

	private static int getSecurityLevel(String securityLevel) {

		if (securityLevel.equals("noAuthNoPriv")) {
			return SecurityLevel.NOAUTH_NOPRIV;
		} else if (securityLevel.equals("authNoPriv")) {
			return SecurityLevel.AUTH_NOPRIV;
		} else {
			return SecurityLevel.AUTH_PRIV;
		}

	}

	private static OID getAuthProtocol(String authProtocol) {

		if (authProtocol == null) {
			return null;
		} else if (authProtocol.equals("MD5")) {
			return (new AuthMD5().getID());
		} else {
			return (new AuthSHA().getID());
		}

	}

	private static OID getPrivProtocol(String privProtocol) {

		if (privProtocol == null) {
			return null;
		} else if (privProtocol.equals("AES")) {
			return PrivAES128.ID;
		} else {
			return PrivDES.ID;
		}

	}

	public byte[] getLocalEngineID() {
		return localEngineID;
	}

}
